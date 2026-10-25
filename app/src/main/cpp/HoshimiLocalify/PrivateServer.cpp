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
#include <atomic>
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
        std::string g_baseAddress;      // IPv4 literal getaddrinfo resolves game hosts to ("" when unused)
        unsigned short g_basePortNumber = 0;
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
        // dump.cs:2041913 for CertificateHandler). These are only fallbacks: Install() resolves
        // the real offsets from il2cpp metadata and only keeps a constant when the lookup fails.
        constexpr std::size_t kUwrPtrOffset = 0x10;
        constexpr std::size_t kUwrCertificateHandlerOffset = 0x28;
        constexpr std::size_t kCertificateHandlerPtrOffset = 0x10;
        constexpr std::size_t kIl2CppArrayLengthOffset = 0x18;
        constexpr std::size_t kIl2CppArrayDataOffset = 0x20;

        // Effective offsets, initialised in Install() before any hook is installed; read-only
        // afterwards, so the worker-thread hooks can read them without locking.
        std::size_t g_uwrPtrOffset = kUwrPtrOffset;
        std::size_t g_uwrCertificateHandlerOffset = kUwrCertificateHandlerOffset;
        std::size_t g_certificateHandlerPtrOffset = kCertificateHandlerPtrOffset;

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

        // Handler mode only: replace the authority with the configured private server. In
        // hostname-preserving mode the URL is left completely untouched (see GetAddrInfo_Hook),
        // because rewriting the port there would also change the Host header for no benefit.
        std::string RewriteUrlForPrivateServer(const std::string& url) {
            std::string path;
            const std::string host = HostOfUrl(url, path);
            if (host.empty()) return url;
            if (!IsRedirectHost(host)) return url;
            return g_baseUrl + path;
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
            void* uwrKlassAddress = nullptr;
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
        std::once_flag g_sharedHandlerOnce;
        void* g_sharedHandler = nullptr;  // kept alive by the pinned GC handle below
        std::uint32_t g_sharedHandlerGcHandle = 0;
        std::atomic<bool> g_surfaceMissingLogged{false};
        std::atomic<int> g_attachLogCount{0};
        std::atomic<int> g_attachErrorCount{0};

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
                g_handlerSurface.uwrKlassAddress = uwr->address;
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

        std::size_t ResolveFieldOffset(void* klass, const char* fieldName, std::size_t fallback,
                                       const char* label) {
            if (klass) {
                auto* field = UnityResolve::Invoke<Il2cppUtils::FieldInfo*>(
                        "il2cpp_class_get_field_from_name", klass, fieldName);
                if (field) {
                    const int offset = UnityResolve::Invoke<int>("il2cpp_field_get_offset", field);
                    // Instance fields live after the 16-byte object header; anything else means
                    // the lookup hit a static field or the metadata call failed.
                    if (offset >= static_cast<int>(2 * sizeof(void*)) && offset <= 0x400) {
                        HoshimiLocal::Log::InfoFmt("PrivateServer: %s offset 0x%x (runtime)", label, offset);
                        return static_cast<std::size_t>(offset);
                    }
                    HoshimiLocal::Log::ErrorFmt("PrivateServer: %s offset %d is unusable; using 0x%zx",
                                                label, offset, fallback);
                    return fallback;
                }
            }
            HoshimiLocal::Log::InfoFmt("PrivateServer: %s not resolvable; using 0x%zx", label, fallback);
            return fallback;
        }

        // Derived once in Install() before the hooks go in, so the worker-thread paths only read
        // already-initialised values. The 6.0.2 dump offsets above stay as a safety net.
        void ResolveFieldOffsets() {
            if (g_handlerSurface.uwrKlassAddress) {
                g_uwrPtrOffset = ResolveFieldOffset(g_handlerSurface.uwrKlassAddress, "m_Ptr",
                                                    kUwrPtrOffset, "UnityWebRequest.m_Ptr");
                g_uwrCertificateHandlerOffset = ResolveFieldOffset(
                        g_handlerSurface.uwrKlassAddress, "m_CertificateHandler",
                        kUwrCertificateHandlerOffset, "UnityWebRequest.m_CertificateHandler");
            }
            if (g_handlerSurface.klassAddress) {
                g_certificateHandlerPtrOffset = ResolveFieldOffset(
                        g_handlerSurface.klassAddress, "m_Ptr", kCertificateHandlerPtrOffset,
                        "CertificateHandler.m_Ptr");
            }
        }

        void* CreateSharedCertificateHandler() {
            std::call_once(g_sharedHandlerOnce, [] {
                if (!g_handlerSurface.Usable()) return;
                void* obj = UnityResolve::Invoke<void*>("il2cpp_object_new", g_handlerSurface.klassAddress);
                if (!obj) {
                    HoshimiLocal::Log::Error("PrivateServer: failed to allocate CertificateHandler");
                    return;
                }
                void* exception = nullptr;
                UnityResolve::Invoke<void*>("il2cpp_runtime_invoke", g_handlerSurface.ctor, obj, nullptr,
                                            &exception);
                if (exception) {
                    HoshimiLocal::Log::Error("PrivateServer: CertificateHandler .ctor threw");
                    return;
                }
                // The ctor is what binds the native object our callback belongs to; without it the
                // managed instance is inert and attaching it would silently disable validation.
                const auto nativePtr = *reinterpret_cast<void**>(
                        reinterpret_cast<char*>(obj) + g_certificateHandlerPtrOffset);
                if (!nativePtr) {
                    HoshimiLocal::Log::Error("PrivateServer: CertificateHandler has no native handle "
                                             "(Create icall missing)");
                    return;
                }
                // Nothing else references the instance once AttachCertificateHandler returns, so it
                // must be pinned for the process lifetime or the GC can collect/move it and leave
                // every request with a dangling m_CertificateHandler.
                const auto handle = UnityResolve::Invoke<std::uint32_t>("il2cpp_gchandle_new", obj, true);
                if (handle == 0) {
                    HoshimiLocal::Log::Error("PrivateServer: il2cpp_gchandle_new unavailable; refusing to "
                                             "cache an unrooted CertificateHandler");
                    return;
                }
                g_sharedHandlerGcHandle = handle;
                g_sharedHandler = obj;
                HoshimiLocal::Log::InfoFmt("PrivateServer: created CertificateHandler %p (native %p, gc handle 0x%x)",
                                           obj, nativePtr, handle);
            });
            return g_sharedHandler;
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
                        reinterpret_cast<char*>(self) + g_uwrPtrOffset);
                const auto nativeHandler = *reinterpret_cast<void**>(
                        reinterpret_cast<char*>(handler) + g_certificateHandlerPtrOffset);
                if (!nativeSelf || !nativeHandler) return -1;
                using SetCertificateHandlerType = int (*)(void*, void*);
                return reinterpret_cast<SetCertificateHandlerType>(g_handlerSurface.setIcall)(
                        nativeSelf, nativeHandler);
            }
            return -1;
        }

        void EnsureCertificateHandler(void* self, const std::string& requestUrl) {
            auto* field = reinterpret_cast<void**>(reinterpret_cast<char*>(self) + g_uwrCertificateHandlerOffset);
            if (*field) return;           // the game (or a previous call) already registered one
            if (g_caPem.empty()) return;  // without a CA we must not divert Unity's default validation
            if (!g_handlerSurface.Usable()) {
                if (!g_surfaceMissingLogged.exchange(true)) {
                    HoshimiLocal::Log::ErrorFmt("PrivateServer: no usable CertificateHandler surface in this build; "
                                                "not attaching a handler (request %s)", requestUrl.c_str());
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
            if (error != 0) {
                const int count = g_attachErrorCount.fetch_add(1) + 1;
                if (count <= 5 || (count % 50) == 0) {
                    HoshimiLocal::Log::ErrorFmt("PrivateServer: attaching CertificateHandler to %s failed: error %d",
                                                requestUrl.c_str(), error);
                }
                return;
            }
            const int count = g_attachLogCount.fetch_add(1) + 1;
            if (count <= 5 || (count % 50) == 0) {
                HoshimiLocal::Log::InfoFmt("PrivateServer: attached CertificateHandler %p to %p for %s",
                                           handler, self, requestUrl.c_str());
            }
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

        // In hostname-preserving mode the URL is deliberately left untouched (hostname and port):
        // rewriting the port would change the Host header while adding no coverage, because the
        // getaddrinfo hook already returns the private address and port for these hosts.
        if (g_preserveHost) return orig(self, mtd);

        std::string currentUrl;
        auto* url = CallGetUrl(self);
        if (url) {
            const std::string original = url->ToString();
            currentUrl = RewriteUrlForPrivateServer(original);
            if (currentUrl != original) {
                CallSetUrl(self, Il2cppString::New(currentUrl.c_str()));
                HoshimiLocal::Log::InfoFmt("PrivateServer: %s -> %s", original.c_str(), currentUrl.c_str());
            }
        }
        EnsureCertificateHandler(self, currentUrl);
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
    // certificate Common Name / TLS SNI still match) and this hook points the connection at the
    // private server. The port is rewritten too: gRPC (YAHA, Rust hyper+rustls) asks for
    // "<host>:443" while only 8443 is forwarded (`adb reverse tcp:8443 tcp:8443`), so every
    // returned sockaddr is forced to g_basePortNumber regardless of the requested service.
    using GetAddrInfoType = int (*)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
    static GetAddrInfoType GetAddrInfo_Orig = nullptr;
    static std::atomic<int> g_resolveLogCount{0};

    static void ForceResolvedPort(struct addrinfo* list) {
        for (auto* ai = list; ai != nullptr; ai = ai->ai_next) {
            if (!ai->ai_addr) continue;
            if (ai->ai_family == AF_INET && ai->ai_addrlen >= sizeof(struct sockaddr_in)) {
                reinterpret_cast<struct sockaddr_in*>(ai->ai_addr)->sin_port = htons(g_basePortNumber);
            }
            else if (ai->ai_family == AF_INET6 && ai->ai_addrlen >= sizeof(struct sockaddr_in6)) {
                reinterpret_cast<struct sockaddr_in6*>(ai->ai_addr)->sin6_port = htons(g_basePortNumber);
            }
        }
    }

    static int GetAddrInfo_Hook(const char* node, const char* service, const struct addrinfo* hints,
                                struct addrinfo** res) {
        if (!GetAddrInfo_Orig) {
            errno = EADDRNOTAVAIL;
            return EAI_FAIL;
        }
        // Everything outside an exact redirected game host - Firebase, Google, id.qseed.jp,
        // CloudFront, literals - goes through the real resolver untouched.
        if (!g_preserveHost || g_baseAddress.empty() || g_basePortNumber == 0 || !node || !*node
                || IsIpv4Literal(node) || !IsRedirectHost(NormalizeHostName(node))) {
            return GetAddrInfo_Orig(node, service, hints, res);
        }

        // The private server is reached over IPv4; if the caller pinned AF_INET6, relax the family
        // instead of failing the connection.
        struct addrinfo adjustedHints {};
        const struct addrinfo* effectiveHints = hints;
        if (hints && hints->ai_family == AF_INET6) {
            adjustedHints = *hints;
            adjustedHints.ai_family = AF_UNSPEC;
            effectiveHints = &adjustedHints;
        }

        // Resolve with the private port so a null / "443" / "https" service cannot leave the
        // socket aimed at <host>:443 where nothing is listening.
        const int result = GetAddrInfo_Orig(g_baseAddress.c_str(), g_basePort.c_str(), effectiveHints, res);
        if (result != 0) {
            const int failures = g_resolveLogCount.fetch_add(1) + 1;
            if (failures <= 10) {
                HoshimiLocal::Log::ErrorFmt("PrivateServer: resolve %s:%s -> %s:%u failed: %d",
                                            node, service ? service : "(null)", g_baseAddress.c_str(),
                                            g_basePortNumber, result);
            }
            return result;
        }
        ForceResolvedPort(*res);
        const int count = g_resolveLogCount.fetch_add(1) + 1;
        if (count <= 10) {
            HoshimiLocal::Log::InfoFmt("PrivateServer: resolve %s:%s -> %s:%u",
                                       node, service ? service : "(null)", g_baseAddress.c_str(),
                                       g_basePortNumber);
        }
        return 0;
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
        // The configured authority only needs to be known as a redirect host in handler mode, when
        // it is a hostname; an IPv4 endpoint is reached directly and would only clutter the list.
        if (!g_baseHost.empty() && !IsIpv4Literal(g_baseHost)
                && std::find(g_redirectHosts.begin(), g_redirectHosts.end(), g_baseHost) == g_redirectHosts.end()) {
            g_redirectHosts.push_back(g_baseHost);
        }

        // Two ways to reach the private server:
        //  * handler mode - the configured authority (usually an IP) is used and our
        //    CertificateHandler decides about the chain;
        //  * hostname-preserving mode - the build has no usable CertificateHandler surface, so the
        //    game's own hostnames are kept in the URL (the certificate Common Name keeps matching)
        //    and the getaddrinfo hook redirects the connection (address and port) instead.
        ProbeCertificateHandlerSurface();
        ResolveFieldOffsets();
        const bool handlerMode = !g_caPem.empty() && g_handlerSurface.Usable();
        g_preserveHost = endpointOk && !handlerMode && g_baseScheme == "https" && IsIpv4Literal(g_baseHost);
        if (g_preserveHost) {
            g_baseAddress = g_baseHost;
        }

        // Every hook below reads g_baseUrl / g_baseAddress / g_redirectHosts / g_preserveHost and the
        // field offsets, so they are all final before the first hook is installed.
        std::string hostList;
        for (const auto& host : g_redirectHosts) {
            if (!hostList.empty()) hostList += ", ";
            hostList += host;
        }
        const char* mode = g_preserveHost ? "preserve-host"
                : (handlerMode ? "certificate-handler" : "url-rewrite-no-handler");
        HoshimiLocal::Log::InfoFmt("PrivateServer: mode=%s redirect=%s:%s hosts=[%s] caPem=%zu bytes",
                                   mode,
                                   g_preserveHost ? g_baseAddress.c_str() : g_baseHost.c_str(),
                                   g_basePort.c_str(), hostList.c_str(), g_caPem.size());
        if (!g_preserveHost && !handlerMode) {
            HoshimiLocal::Log::Error("PrivateServer: no usable CertificateHandler and the endpoint is not an "
                                     "IPv4 literal; TLS will fall back to the system trust store");
        }

        if (g_preserveHost) {
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
            // Only getaddrinfo is hooked: it is the resolver both libcurl and gRPC go through, and
            // rewriting address plus port there makes a separate (and over-broad) connect() hook
            // unnecessary. Non-game traffic never reaches this branch.
            installSymbolHook("libc.so", "getaddrinfo", reinterpret_cast<void*>(&GetAddrInfo_Hook),
                              reinterpret_cast<void**>(&GetAddrInfo_Orig));
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
