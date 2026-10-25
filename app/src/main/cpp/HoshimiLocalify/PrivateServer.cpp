#include "PrivateServer.hpp"

#include "Plugin.h"
#include "Log.h"
#include "Il2cppUtils.hpp"
#include "PrivateServerCert.hpp"
#include "config/Config.hpp"
#include "shadowhook.h"
#include "../deps/UnityResolve/UnityResolve.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <mutex>
#include <string>
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
        constexpr std::size_t kUwrCertificateHandlerOffset = 0x28;
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

        std::string RewriteUrlForPrivateServer(const std::string& url) {
            std::string path;
            const std::string host = HostOfUrl(url, path);
            if (host.empty()) return url;
            for (const auto& candidate : g_redirectHosts) {
                if (host == candidate) return g_baseUrl + path;
            }
            return url;
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

        void EnsureCertificateHandler(void* self) {
            if (g_caPem.empty()) return;  // without a CA we must not divert Unity's default validation
            auto* field = reinterpret_cast<void**>(reinterpret_cast<char*>(self) + kUwrCertificateHandlerOffset);
            if (*field) return;
            auto klass = Il2cppUtils::GetClass("UnityEngine.UnityWebRequestModule.dll",
                                               "UnityEngine.Networking", "CertificateHandler");
            if (!klass) {
                HoshimiLocal::Log::Error("PrivateServer: CertificateHandler class not found");
                return;
            }
            void* obj = UnityResolve::Invoke<void*>("il2cpp_object_new", klass->address);
            if (!obj) {
                HoshimiLocal::Log::Error("PrivateServer: failed to allocate CertificateHandler");
                return;
            }
            auto* ctor = Il2cppUtils::il2cpp_class_get_method_from_name(klass->address, ".ctor", 0);
            if (ctor) {
                void* exception = nullptr;
                UnityResolve::Invoke<void*>("il2cpp_runtime_invoke", ctor, obj, nullptr, &exception);
                if (exception) {
                    HoshimiLocal::Log::Error("PrivateServer: CertificateHandler ctor threw");
                    return;
                }
            }
            else {
                HoshimiLocal::Log::Error("PrivateServer: CertificateHandler .ctor not found");
            }
            {
                std::lock_guard<std::mutex> lock(g_handlerMutex);
                g_ownCertificateHandlers.insert(obj);
            }
            *field = obj;
            HoshimiLocal::Log::InfoFmt("PrivateServer: attached CertificateHandler for %p", self);
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
        EnsureCertificateHandler(self);
        return orig(self, mtd);
    }

    PS_DEFINE_HOOK(bool, CertificateHandler_ValidateCertificate,
                   (void* self, void* certificateData, void* mtd)) {
        if (g_caPem.empty()) {
            return CertificateHandler_ValidateCertificate_Orig
                    ? CertificateHandler_ValidateCertificate_Orig(self, certificateData, mtd) : false;
        }
        bool ours = false;
        {
            std::lock_guard<std::mutex> lock(g_handlerMutex);
            ours = g_ownCertificateHandlers.count(self) != 0;
        }
        if (!ours) {
            return CertificateHandler_ValidateCertificate_Orig
                    ? CertificateHandler_ValidateCertificate_Orig(self, certificateData, mtd) : false;
        }
        if (!certificateData) return false;
        const auto* array = static_cast<const Il2CppArrayLayout*>(
                static_cast<const void*>(certificateData));
        const auto length = *reinterpret_cast<const std::uintptr_t*>(
                reinterpret_cast<const char*>(array) + kIl2CppArrayLengthOffset);
        const auto* data = reinterpret_cast<const unsigned char*>(
                reinterpret_cast<const char*>(array) + kIl2CppArrayDataOffset);
        if (length == 0) return false;
        const bool accepted = VerifyChainAgainstPem(data, length, g_caPem);
        HoshimiLocal::Log::InfoFmt("PrivateServer: certificate %s", accepted ? "accepted" : "rejected");
        return accepted;
    }

    PS_DEFINE_HOOK(Il2cppString*, Api_GetHost, (void* self, void* mtd)) {
        auto orig = Api_GetHost_Orig ? Api_GetHost_Orig(self, mtd) : nullptr;
        if (g_baseUrl.empty()) return orig;
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
        if (g_baseUrl.empty()) return orig;
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

        g_redirectHosts = {"api.game-idolypride.jp", "climaster.game-idolypride.jp", "api.octo-cloud.com"};
        std::string basePath;
        const std::string baseHost = HostOfUrl(g_baseUrl, basePath);
        if (!baseHost.empty() && std::find(g_redirectHosts.begin(), g_redirectHosts.end(), baseHost)
                == g_redirectHosts.end()) {
            g_redirectHosts.push_back(baseHost);
        }

        PS_ADD_HOOK(Api_GetHost, Il2cppUtils::GetMethodPointer(
                "Assembly-CSharp.dll", "Solis.Common.Network", "Api", "GetHost"));
        PS_ADD_HOOK(Api_GetSSLRootCertificates, Il2cppUtils::GetMethodPointer(
                "Assembly-CSharp.dll", "Solis.Common.Network", "Api", "GetSSLRootCertificates"));
        PS_ADD_HOOK(OctoSettings_get_Url, FindOctoUrlGetter());
        PS_ADD_HOOK(Uwr_SendWebRequest, Il2cppUtils::GetMethodPointer(
                "UnityEngine.UnityWebRequestModule.dll", "UnityEngine.Networking",
                "UnityWebRequest", "SendWebRequest"));
        PS_ADD_HOOK(CertificateHandler_ValidateCertificate, Il2cppUtils::GetMethodPointer(
                "UnityEngine.UnityWebRequestModule.dll", "UnityEngine.Networking",
                "CertificateHandler", "ValidateCertificate"));
    }
}
