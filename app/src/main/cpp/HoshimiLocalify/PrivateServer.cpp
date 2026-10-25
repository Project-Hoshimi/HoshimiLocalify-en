#include "PrivateServer.hpp"

#include "Plugin.h"
#include "Log.h"
#include "Il2cppUtils.hpp"
#include "PrivateServerCert.hpp"
#include "config/Config.hpp"
#include "shadowhook.h"
#include "../deps/UnityResolve/UnityResolve.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unordered_set>
#include <vector>

namespace HoshimiLocal::PrivateServer {
    using Il2cppString = UnityResolve::UnityType::String;

#define PS_DEFINE_HOOK(returnType, name, params)                                                   \
    using name##_Type = returnType (*) params;                                                     \
    static name##_Type name##_Orig = nullptr;                                                      \
    static returnType name##_Hook params

#define PS_ADD_HOOK(name, addr)                                                                    \
    do {                                                                                           \
        if (addr) {                                                                                \
            auto stub = hookInstaller->InstallHook(reinterpret_cast<void*>(addr),                   \
                                                   reinterpret_cast<void*>(name##_Hook),            \
                                                   reinterpret_cast<void**>(&name##_Orig));         \
            if (stub == nullptr) {                                                                 \
                const int errorNum = shadowhook_get_errno();                                       \
                HoshimiLocal::Log::ErrorFmt("PrivateServer: hook %s failed: %s", #name,             \
                                            shadowhook_to_errmsg(errorNum));                       \
            }                                                                                      \
            else {                                                                                 \
                HoshimiLocal::Log::InfoFmt("PrivateServer: hook %s installed", #name);              \
            }                                                                                      \
        }                                                                                          \
        else {                                                                                     \
            HoshimiLocal::Log::ErrorFmt("PrivateServer: %s address not found", #name);              \
        }                                                                                          \
    } while (0)

    namespace {
        std::string g_baseUrl;   // normalized: no trailing slash
        std::string g_caPem;     // trimmed configured PEM

        // Private server endpoint, parsed once in Install().
        std::string g_baseScheme;       // "https"
        std::string g_baseHost;         // lowercase host of g_baseUrl ("127.0.0.1")
        std::string g_basePort;         // port of g_baseUrl as text ("8443")
        std::string g_baseAddress;      // IPv4 literal we redirect connections to ("" when unused)
        unsigned short g_basePortNumber = 0;
        in_addr_t g_baseAddrIpv4 = 0;
        // Set when we cannot hand Unity a CertificateHandler: the game's own hostnames are kept in
        // the request URL (so the server certificate's Common Name still matches) and the
        // connection is redirected to g_baseAddress instead.
        bool g_preserveHost = false;

        static std::string Trim(const std::string& s) {
            const std::string ws = " \t\r\n";
            const auto start = s.find_first_not_of(ws);
            if (start == std::string::npos) return "";
            const auto end = s.find_last_not_of(ws);
            return s.substr(start, end - start + 1);
        }

        std::string NormalizeBaseUrl(const std::string& raw) {
            std::string s = Trim(raw);
            while (!s.empty() && s.back() == '/') s.pop_back();
            return s;
        }

        // Splits "scheme://authority" into scheme/host/port; the port falls back to the scheme
        // default. Returns false when the URL has no usable authority.
        bool ParseEndpoint(const std::string& url, std::string& scheme, std::string& host,
                           std::string& port, unsigned short& portNumber) {
            const auto schemeEnd = url.find("://");
            if (schemeEnd == std::string::npos) return false;
            scheme = url.substr(0, schemeEnd);
            const auto authorityStart = schemeEnd + 3;
            const auto authorityEnd = url.find('/', authorityStart);
            std::string authority = url.substr(authorityStart, authorityEnd == std::string::npos
                    ? std::string::npos : authorityEnd - authorityStart);
            const auto at = authority.rfind('@');
            if (at != std::string::npos) authority = authority.substr(at + 1);
            const auto colon = authority.find(':');
            if (colon == std::string::npos) {
                host = authority;
                const bool tls = scheme == "https";
                port = tls ? "443" : "80";
                portNumber = static_cast<unsigned short>(tls ? 443 : 80);
            }
            else {
                host = authority.substr(0, colon);
                port = authority.substr(colon + 1);
                const long value = std::strtol(port.c_str(), nullptr, 10);
                if (value <= 0 || value > 65535) return false;
                portNumber = static_cast<unsigned short>(value);
            }
            return !host.empty();
        }

        // Dotted-quad literals only: that is the case where the URL host and the certificate name
        // disagree, i.e. exactly the configuration that needs hostname-preserving redirection.
        bool IsIpv4Literal(const std::string& host) {
            int parts = 0;
            std::size_t pos = 0;
            while (pos < host.size()) {
                const auto dot = host.find('.', pos);
                const std::string piece = host.substr(pos, dot == std::string::npos
                        ? std::string::npos : dot - pos);
                if (piece.empty() || piece.size() > 3) return false;
                for (const char c : piece) {
                    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
                }
                if (std::strtol(piece.c_str(), nullptr, 10) > 255) return false;
                ++parts;
                if (dot == std::string::npos) break;
                pos = dot + 1;
            }
            return parts == 4;
        }

        std::string FirstPemBodyLine(const std::string& pem) {
            const std::string begin = "-----BEGIN CERTIFICATE-----";
            const auto beginPos = pem.find(begin);
            if (beginPos == std::string::npos) return "";
            auto pos = beginPos + begin.size();
            while (pos < pem.size()) {
                const auto lineEnd = pem.find('\n', pos);
                const std::string line = Trim(
                        pem.substr(pos, lineEnd == std::string::npos ? std::string::npos : lineEnd - pos));
                if (!line.empty()) return line;
                if (lineEnd == std::string::npos) break;
                pos = lineEnd + 1;
            }
            return "";
        }
    }

    namespace {
        // Field offsets from the 6.0.2 arm64 dump (dump.cs:2042201 for UnityWebRequest,
        // dump.cs:2041913 for CertificateHandler).
        constexpr std::size_t kUwrPtrOffset = 0x10;
        constexpr std::size_t kUwrCertificateHandlerOffset = 0x28;
        constexpr std::size_t kCertificateHandlerPtrOffset = 0x10;
        constexpr std::size_t kIl2CppArrayLengthOffset = 0x18;
        constexpr std::size_t kIl2CppArrayDataOffset = 0x20;

        std::mutex g_handlerMutex;
        std::unordered_set<void*> g_ownCertificateHandlers;
        std::vector<std::string> g_redirectHosts;

        std::string Lower(std::string value) {
            for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return value;
        }

        // Splits "scheme://authority/path?query" into lowercase host + path (always starts with '/').
        std::string HostOfUrl(const std::string& url, std::string& path) {
            path = "/";
            const auto scheme = url.find("://");
            if (scheme == std::string::npos) return "";
            const auto authorityStart = scheme + 3;
            const auto pathStart = url.find('/', authorityStart);
            std::string authority = url.substr(authorityStart, pathStart == std::string::npos
                    ? std::string::npos : pathStart - authorityStart);
            if (pathStart != std::string::npos) path = url.substr(pathStart);
            const auto at = authority.rfind('@');
            if (at != std::string::npos) authority = authority.substr(at + 1);
            const auto colon = authority.find(':');
            if (colon != std::string::npos) authority = authority.substr(0, colon);
            return Lower(authority);
        }

        // Lowercase host names for comparison; a trailing root dot does not change the identity.
        std::string NormalizeHostName(const std::string& value) {
            std::string host = Lower(value);
            if (!host.empty() && host.back() == '.') host.pop_back();
            return host;
        }

        bool IsRedirectHost(const std::string& host) {
            for (const auto& candidate : g_redirectHosts) {
                if (host == candidate) return true;
            }
            return false;
        }

        std::string RewriteUrlForPrivateServer(const std::string& url) {
            std::string path;
            const std::string host = HostOfUrl(url, path);
            if (host.empty()) return url;
            if (!IsRedirectHost(host)) return url;
            if (!g_preserveHost) return g_baseUrl + path;
            // Hostname-preserving mode: keep the game's Host header and TLS SNI so the server
            // certificate's Common Name still matches, and only swap in the private server port.
            // The getaddrinfo/connect hooks send the connection to g_baseAddress.
            if (url.compare(0, 6, "https:") != 0) return g_baseUrl + path;
            return "https://" + host + ":" + g_basePort + path;
        }

        struct Il2CppArrayLayout {
            void* klass;
            void* monitor;
            void* bounds;
            std::uintptr_t maxLength;
        };

        Il2cppString* CallGetUrl(void* self) {
            auto klass = Il2cppUtils::GetClass("UnityEngine.UnityWebRequestModule.dll",
                                               "UnityEngine.Networking", "UnityWebRequest");
            if (!klass) return nullptr;
            auto* method = Il2cppUtils::il2cpp_class_get_method_from_name(klass->address, "get_url", 0);
            if (!method) return nullptr;
            using GetUrlType = Il2cppString* (*)(void*, void*);
            return reinterpret_cast<GetUrlType>(method->methodPointer)(self, method);
        }

        void CallSetUrl(void* self, Il2cppString* value) {
            auto klass = Il2cppUtils::GetClass("UnityEngine.UnityWebRequestModule.dll",
                                               "UnityEngine.Networking", "UnityWebRequest");
            if (!klass) return;
            auto* method = Il2cppUtils::il2cpp_class_get_method_from_name(klass->address, "set_url", 1);
            if (!method) return;
            using SetUrlType = void (*)(void*, Il2cppString*, void*);
            reinterpret_cast<SetUrlType>(method->methodPointer)(self, value, method);
        }

        // ---- CertificateHandler plumbing ----
        // A managed CertificateHandler only works when the build kept three pieces:
        //   * the .ctor (it runs the Create icall that allocates the native object),
        //   * the "CertificateHandler::Create" icall itself (fills m_Ptr) and
        //   * an attach entry point (managed set_certificateHandler, else the
        //     UnityWebRequest::SetCertificateHandler icall).
        // Writing UnityWebRequest.m_CertificateHandler alone is invisible to the native request, and
        // some builds strip all three (6.0.3 keeps only Release/ValidateCertificate/Dispose), so the
        // surface is probed once and the caller falls back when it is incomplete.
        struct CertificateHandlerSurface {
            void* klassAddress = nullptr;
            void* ctor = nullptr;
            void* createIcall = nullptr;
            void* setter = nullptr;    // managed set_certificateHandler (MethodInfo*)
            void* setIcall = nullptr;  // native UnityWebRequest::SetCertificateHandler
            bool checked = false;

            bool Usable() const {
                return klassAddress != nullptr && ctor != nullptr && createIcall != nullptr
                        && (setter != nullptr || setIcall != nullptr);
            }
        };

        CertificateHandlerSurface g_handlerSurface;
        void* g_sharedHandler = nullptr;      // one handler is enough, it is stateless
        bool g_surfaceMissingLogged = false;
        int g_attachLogCount = 0;

        void ProbeCertificateHandlerSurface() {
            if (g_handlerSurface.checked) return;
            g_handlerSurface.checked = true;
            auto handlerKlass = Il2cppUtils::GetClass("UnityEngine.UnityWebRequestModule.dll",
                                                      "UnityEngine.Networking", "CertificateHandler");
            if (handlerKlass) {
                g_handlerSurface.klassAddress = handlerKlass->address;
                g_handlerSurface.ctor = Il2cppUtils::il2cpp_class_get_method_from_name(
                        handlerKlass->address, ".ctor", 0);
                g_handlerSurface.createIcall = Il2cppUtils::il2cpp_resolve_icall(
                        "UnityEngine.Networking.CertificateHandler::Create");
            }
            auto uwr = Il2cppUtils::GetClass("UnityEngine.UnityWebRequestModule.dll",
                                             "UnityEngine.Networking", "UnityWebRequest");
            if (uwr) {
                g_handlerSurface.setter = Il2cppUtils::il2cpp_class_get_method_from_name(
                        uwr->address, "set_certificateHandler", 1);
            }
            if (!g_handlerSurface.setter) {
                g_handlerSurface.setIcall = Il2cppUtils::il2cpp_resolve_icall(
                        "UnityEngine.Networking.UnityWebRequest::SetCertificateHandler");
            }
            HoshimiLocal::Log::InfoFmt("PrivateServer: CertificateHandler surface ctor=%s create=%s attach=%s",
                                       g_handlerSurface.ctor ? "yes" : "no",
                                       g_handlerSurface.createIcall ? "yes" : "no",
                                       g_handlerSurface.setter ? "managed-setter"
                                               : (g_handlerSurface.setIcall ? "icall" : "none"));
        }

        void* CreateSharedCertificateHandler() {
            if (g_sharedHandler) return g_sharedHandler;
            if (!g_handlerSurface.Usable()) return nullptr;
            void* obj = UnityResolve::Invoke<void*>("il2cpp_object_new", g_handlerSurface.klassAddress);
            if (!obj) {
                HoshimiLocal::Log::Error("PrivateServer: failed to allocate CertificateHandler");
                return nullptr;
            }
            void* exception = nullptr;
            UnityResolve::Invoke<void*>("il2cpp_runtime_invoke", g_handlerSurface.ctor, obj, nullptr, &exception);
            if (exception) {
                HoshimiLocal::Log::Error("PrivateServer: CertificateHandler .ctor threw");
                return nullptr;
            }
            // The ctor is what binds the native object our callback belongs to; without it the
            // managed instance is inert and attaching it would silently disable validation.
            const auto nativePtr = *reinterpret_cast<void**>(
                    reinterpret_cast<char*>(obj) + kCertificateHandlerPtrOffset);
            if (!nativePtr) {
                HoshimiLocal::Log::Error("PrivateServer: CertificateHandler has no native handle (Create icall missing)");
                return nullptr;
            }
            g_sharedHandler = obj;
            HoshimiLocal::Log::InfoFmt("PrivateServer: created CertificateHandler %p (native %p)", obj, nativePtr);
            return obj;
        }

        // Registers the handler on the native request. Returns UnityWebRequestError (0 == ok),
        // or -1 when no attach path exists / the pointers are unusable.
        int AttachCertificateHandler(void* self, void* handler) {
            if (!self || !handler) return -1;
            if (g_handlerSurface.setter) {
                void* exception = nullptr;
                void* handlerArg = handler;             // il2cpp_runtime_invoke wants the address of each arg
                void* args[1] = { &handlerArg };
                UnityResolve::Invoke<void*>("il2cpp_runtime_invoke", g_handlerSurface.setter, self, args, &exception);
                // The setter throws before touching native state when the request is already sent.
                return exception ? 6 : 0;
            }
            if (g_handlerSurface.setIcall) {
                const auto nativeSelf = *reinterpret_cast<void**>(
                        reinterpret_cast<char*>(self) + kUwrPtrOffset);
                const auto nativeHandler = *reinterpret_cast<void**>(
                        reinterpret_cast<char*>(handler) + kCertificateHandlerPtrOffset);
                if (!nativeSelf || !nativeHandler) return -1;
                using SetCertificateHandlerType = int (*)(void*, void*);
                return reinterpret_cast<SetCertificateHandlerType>(g_handlerSurface.setIcall)(
                        nativeSelf, nativeHandler);
            }
            return -1;
        }

        void EnsureCertificateHandler(void* self) {
            auto* field = reinterpret_cast<void**>(reinterpret_cast<char*>(self) + kUwrCertificateHandlerOffset);
            if (*field) return;           // the game (or a previous call) already registered one
            if (g_caPem.empty()) return;  // without a CA we must not divert Unity's default validation
            if (!g_handlerSurface.Usable()) {
                if (!g_surfaceMissingLogged) {
                    g_surfaceMissingLogged = true;
                    HoshimiLocal::Log::Error("PrivateServer: no usable CertificateHandler surface in this build; "
                                             "not attaching a handler");
                }
                return;
            }
            void* handler = CreateSharedCertificateHandler();
            if (!handler) return;
            {
                std::lock_guard<std::mutex> lock(g_handlerMutex);
                g_ownCertificateHandlers.insert(handler);
            }
            const int error = AttachCertificateHandler(self, handler);
            // Rate-limited: high traffic would otherwise flood logcat with one line per request.
            if (g_attachLogCount < 5 || (g_attachLogCount % 50) == 0) {
                HoshimiLocal::Log::InfoFmt("PrivateServer: attach CertificateHandler %p to %p -> error %d",
                                           handler, self, error);
            }
            ++g_attachLogCount;
        }

        bool IsOwnCertificateHandler(void* self) {
            std::lock_guard<std::mutex> lock(g_handlerMutex);
            return g_ownCertificateHandlers.count(self) != 0;
        }

        // Verifies the presented chain against the configured CA. Called from both managed entry
        // points; returns false whenever the chain cannot be trusted.
        bool EvaluateCertificate(void* self, const char* entry, void* certificateData) {
            if (!certificateData || g_caPem.empty()) return false;
            const auto* array = static_cast<const Il2CppArrayLayout*>(
                    static_cast<const void*>(certificateData));
            const auto length = *reinterpret_cast<const std::uintptr_t*>(
                    reinterpret_cast<const char*>(array) + kIl2CppArrayLengthOffset);
            const auto* data = reinterpret_cast<const unsigned char*>(
                    reinterpret_cast<const char*>(array) + kIl2CppArrayDataOffset);
            if (length == 0) return false;
            const bool accepted = VerifyChainAgainstPem(data, length, g_caPem);
            HoshimiLocal::Log::InfoFmt("PrivateServer: certificate %s (handler %p, %zu bytes, %s)",
                                       accepted ? "accepted" : "rejected", self, static_cast<std::size_t>(length),
                                       entry);
            return accepted;
        }
    }

    PS_DEFINE_HOOK(void*, Uwr_SendWebRequest, (void* self, void* mtd)) {
        auto orig = Uwr_SendWebRequest_Orig;
        if (!orig) return nullptr;
        if (!self) return orig(self, mtd);

        auto* url = CallGetUrl(self);
        if (url) {
            const std::string original = url->ToString();
            const std::string rewritten = RewriteUrlForPrivateServer(original);
            if (rewritten != original) {
                CallSetUrl(self, Il2cppString::New(rewritten.c_str()));
                HoshimiLocal::Log::InfoFmt("PrivateServer: %s -> %s", original.c_str(), rewritten.c_str());
            }
        }
        // In hostname-preserving mode there is no handler surface to use; Unity validates against
        // the system trust store plus the CA injected through Api.GetSSLRootCertificates.
        if (!g_preserveHost) EnsureCertificateHandler(self);
        return orig(self, mtd);
    }

    // The native side validates through ValidateCertificateNative ([RequiredByNativeCode]), which
    // dispatches to the virtual ValidateCertificate. Both entry points are hooked so the verdict
    // holds either way; handlers that are not ours keep Unity's original behaviour.
    PS_DEFINE_HOOK(bool, CertificateHandler_ValidateCertificateNative,
                   (void* self, void* certificateData, void* mtd)) {
        if (IsOwnCertificateHandler(self)) {
            return EvaluateCertificate(self, "ValidateCertificateNative", certificateData);
        }
        return CertificateHandler_ValidateCertificateNative_Orig
                ? CertificateHandler_ValidateCertificateNative_Orig(self, certificateData, mtd) : false;
    }

    PS_DEFINE_HOOK(bool, CertificateHandler_ValidateCertificate,
                   (void* self, void* certificateData, void* mtd)) {
        if (IsOwnCertificateHandler(self)) {
            return EvaluateCertificate(self, "ValidateCertificate", certificateData);
        }
        return CertificateHandler_ValidateCertificate_Orig
                ? CertificateHandler_ValidateCertificate_Orig(self, certificateData, mtd) : false;
    }

    // ---- Hostname-preserving redirection ----
    // Used when no CertificateHandler can be attached: the URL keeps the game's hostname (so the
    // certificate Common Name matches) and these hooks point the connection at the private server.
    // getaddrinfo covers curl's resolver, connect() also catches pre-resolved addresses.
    using GetAddrInfoType = int (*)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
    static GetAddrInfoType GetAddrInfo_Orig = nullptr;
    static int g_resolveLogCount = 0;

    static int GetAddrInfo_Hook(const char* node, const char* service, const struct addrinfo* hints,
                                struct addrinfo** res) {
        if (!GetAddrInfo_Orig) {
            errno = EADDRNOTAVAIL;
            return EAI_FAIL;
        }
        if (g_baseAddress.empty() || !node || !*node || IsIpv4Literal(node)) {
            return GetAddrInfo_Orig(node, service, hints, res);
        }
        if (!IsRedirectHost(NormalizeHostName(node))) {
            return GetAddrInfo_Orig(node, service, hints, res);
        }
        if (g_resolveLogCount < 10) {
            HoshimiLocal::Log::InfoFmt("PrivateServer: resolve %s -> %s", node, g_baseAddress.c_str());
            ++g_resolveLogCount;
        }
        return GetAddrInfo_Orig(g_baseAddress.c_str(), service, hints, res);
    }

    using ConnectType = int (*)(int, const struct sockaddr*, socklen_t);
    static ConnectType Connect_Orig = nullptr;
    static int g_connectLogCount = 0;

    static int Connect_Hook(int fd, const struct sockaddr* addr, socklen_t len) {
        if (!Connect_Orig) {
            errno = EBADF;
            return -1;
        }
        if (!g_baseAddress.empty() && g_basePortNumber != 0 && g_baseAddrIpv4 != 0 && addr
                && addr->sa_family == AF_INET
                && len >= static_cast<socklen_t>(sizeof(struct sockaddr_in))) {
            const auto* sin = reinterpret_cast<const struct sockaddr_in*>(addr);
            if (ntohs(sin->sin_port) == g_basePortNumber && sin->sin_addr.s_addr != g_baseAddrIpv4) {
                struct sockaddr_in local = *sin;
                local.sin_addr.s_addr = g_baseAddrIpv4;
                if (g_connectLogCount < 10) {
                    HoshimiLocal::Log::InfoFmt("PrivateServer: connect fd %d redirected to %s:%u",
                                               fd, g_baseAddress.c_str(), g_basePortNumber);
                    ++g_connectLogCount;
                }
                return Connect_Orig(fd, reinterpret_cast<const struct sockaddr*>(&local), sizeof(local));
            }
        }
        return Connect_Orig(fd, addr, len);
    }

    PS_DEFINE_HOOK(Il2cppString*, Api_GetHost, (void* self, void* mtd)) {
        auto orig = Api_GetHost_Orig ? Api_GetHost_Orig(self, mtd) : nullptr;
        if (g_baseUrl.empty() || g_preserveHost) return orig;
        HoshimiLocal::Log::InfoFmt("PrivateServer: GetHost -> %s", g_baseUrl.c_str());
        return Il2cppString::New(g_baseUrl.c_str());
    }

    PS_DEFINE_HOOK(Il2cppString*, Api_GetSSLRootCertificates, (void* self, void* mtd)) {
        auto orig = Api_GetSSLRootCertificates_Orig ? Api_GetSSLRootCertificates_Orig(self, mtd) : nullptr;
        const std::string origStr = orig ? orig->ToString() : std::string();
        if (g_caPem.empty()) return orig;

        // The game bundle's bundle string often lacks a trailing END line, so appending our CA
        // would be silently dropped: our CA must come FIRST.
        const std::string marker = FirstPemBodyLine(g_caPem);
        if (!marker.empty() && origStr.find(marker) != std::string::npos) return orig;

        std::string combined = g_caPem;
        if (!origStr.empty()) combined += "\n" + origStr + "\n";
        return Il2cppString::New(combined.c_str());
    }

    PS_DEFINE_HOOK(Il2cppString*, OctoSettings_get_Url, (void* self, void* mtd)) {
        auto orig = OctoSettings_get_Url_Orig ? OctoSettings_get_Url_Orig(self, mtd) : nullptr;
        if (g_baseUrl.empty() || g_preserveHost) return orig;
        const std::string origStr = orig ? orig->ToString() : std::string();
        // Keep the path (and query) of the original URL, replace scheme + authority.
        std::string path = "/";
        const auto scheme = origStr.find("://");
        const auto hostStart = scheme == std::string::npos ? 0 : scheme + 3;
        const auto slash = origStr.find('/', hostStart);
        if (slash != std::string::npos) path = origStr.substr(slash);
        const std::string rewritten = g_baseUrl + path;
        HoshimiLocal::Log::InfoFmt("PrivateServer: OctoSettings.url %s -> %s", origStr.c_str(), rewritten.c_str());
        return Il2cppString::New(rewritten.c_str());
    }

    // OctoSettings.get_Url is an explicit interface implementation whose il2cpp name is
    // "Octo.IOctoSettings.get_Url"; fall back to scanning the class by suffix if lookup fails.
    void* FindOctoUrlGetter() {
        void* p = Il2cppUtils::GetMethodPointer("Octo.dll", "Octo", "OctoSettings", "Octo.IOctoSettings.get_Url");
        if (p) return p;
        auto klass = Il2cppUtils::GetClass("Octo.dll", "Octo", "OctoSettings");
        if (!klass) return nullptr;
        void* iter = nullptr;
        while (auto* m = UnityResolve::Invoke<Il2cppUtils::MethodInfo*>(
                   "il2cpp_class_get_methods", klass->address, &iter)) {
            if (m->name && std::string(m->name).find("get_Url") != std::string::npos) {
                return reinterpret_cast<void*>(m->methodPointer);
            }
        }
        return nullptr;
    }

    void Install(HookInstaller* hookInstaller) {
        if (!Config::privateServerEnabled) return;
        g_baseUrl = NormalizeBaseUrl(Config::privateServerUrl);
        g_caPem = Config::privateServerCaPem;
        // trim trailing newlines only
        while (!g_caPem.empty() && (g_caPem.back() == '\n' || g_caPem.back() == '\r')) g_caPem.pop_back();
        if (g_baseUrl.empty()) {
            HoshimiLocal::Log::Error("PrivateServer: enabled but URL is empty; not installing hooks");
            return;
        }
        HoshimiLocal::Log::InfoFmt("PrivateServer: installing hooks for %s (caPem=%zu bytes)",
                                   g_baseUrl.c_str(), g_caPem.size());

        std::string baseHost, basePort;
        const bool endpointOk = ParseEndpoint(g_baseUrl, g_baseScheme, baseHost, basePort, g_basePortNumber);
        g_baseHost = Lower(baseHost);
        g_basePort = basePort;
        if (!endpointOk) {
            HoshimiLocal::Log::ErrorFmt("PrivateServer: cannot parse the endpoint of %s", g_baseUrl.c_str());
        }

        g_redirectHosts = {"api.game-idolypride.jp", "climaster.game-idolypride.jp", "api.octo-cloud.com"};
        if (!g_baseHost.empty() && std::find(g_redirectHosts.begin(), g_redirectHosts.end(), g_baseHost)
                == g_redirectHosts.end()) {
            g_redirectHosts.push_back(g_baseHost);
        }

        // Two ways to reach the private server:
        //  * handler mode - the configured authority (usually an IP) is used and our
        //    CertificateHandler decides about the chain;
        //  * hostname-preserving mode - the build has no usable CertificateHandler surface, so the
        //    game's own hostnames are kept in the URL (the certificate Common Name keeps matching)
        //    and the connection is redirected to the configured address instead.
        ProbeCertificateHandlerSurface();
        const bool handlerMode = !g_caPem.empty() && g_handlerSurface.Usable();
        g_preserveHost = endpointOk && !handlerMode && g_baseScheme == "https" && IsIpv4Literal(g_baseHost);
        if (g_preserveHost) {
            g_baseAddress = g_baseHost;
            struct in_addr parsedAddress {};
            if (inet_pton(AF_INET, g_baseAddress.c_str(), &parsedAddress) == 1) {
                g_baseAddrIpv4 = parsedAddress.s_addr;
            }
            HoshimiLocal::Log::InfoFmt("PrivateServer: preserving game hostnames; connections go to %s:%u",
                                       g_baseAddress.c_str(), g_basePortNumber);
            auto installSymbolHook = [](const char* libName, const char* symName, void* hook, void** orig) {
                if (shadowhook_hook_sym_name(libName, symName, hook, orig) == nullptr) {
                    const int errorNum = shadowhook_get_errno();
                    HoshimiLocal::Log::ErrorFmt("PrivateServer: hook %s failed: %s", symName,
                                                shadowhook_to_errmsg(errorNum));
                }
                else {
                    HoshimiLocal::Log::InfoFmt("PrivateServer: hook %s installed", symName);
                }
            };
            installSymbolHook("libc.so", "getaddrinfo", reinterpret_cast<void*>(&GetAddrInfo_Hook),
                              reinterpret_cast<void**>(&GetAddrInfo_Orig));
            installSymbolHook("libc.so", "connect", reinterpret_cast<void*>(&Connect_Hook),
                              reinterpret_cast<void**>(&Connect_Orig));
        }
        else {
            HoshimiLocal::Log::Info("PrivateServer: URL authority replaced, validation via CertificateHandler");
        }

        if (g_preserveHost) {
            // Keep the game's own URLs: rewriting the authority would break the Common Name check.
            HoshimiLocal::Log::Info("PrivateServer: GetHost/OctoSettings.url overrides disabled");
        }
        else {
            PS_ADD_HOOK(Api_GetHost, Il2cppUtils::GetMethodPointer(
                    "Assembly-CSharp.dll", "Solis.Common.Network", "Api", "GetHost"));
            PS_ADD_HOOK(OctoSettings_get_Url, FindOctoUrlGetter());
        }
        PS_ADD_HOOK(Api_GetSSLRootCertificates, Il2cppUtils::GetMethodPointer(
                "Assembly-CSharp.dll", "Solis.Common.Network", "Api", "GetSSLRootCertificates"));
        PS_ADD_HOOK(Uwr_SendWebRequest, Il2cppUtils::GetMethodPointer(
                "UnityEngine.UnityWebRequestModule.dll", "UnityEngine.Networking",
                "UnityWebRequest", "SendWebRequest"));
        PS_ADD_HOOK(CertificateHandler_ValidateCertificate, Il2cppUtils::GetMethodPointer(
                "UnityEngine.UnityWebRequestModule.dll", "UnityEngine.Networking",
                "CertificateHandler", "ValidateCertificate"));
        PS_ADD_HOOK(CertificateHandler_ValidateCertificateNative, Il2cppUtils::GetMethodPointer(
                "UnityEngine.UnityWebRequestModule.dll", "UnityEngine.Networking",
                "CertificateHandler", "ValidateCertificateNative"));
    }
}
