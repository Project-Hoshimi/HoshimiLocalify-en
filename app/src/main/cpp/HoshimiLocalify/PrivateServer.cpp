#include "PrivateServer.hpp"

#include "Plugin.h"
#include "Log.h"
#include "Il2cppUtils.hpp"
#include "config/Config.hpp"
#include "shadowhook.h"
#include "../deps/UnityResolve/UnityResolve.hpp"

#include <string>

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

        PS_ADD_HOOK(Api_GetHost, Il2cppUtils::GetMethodPointer(
                "Assembly-CSharp.dll", "Solis.Common.Network", "Api", "GetHost"));
        PS_ADD_HOOK(Api_GetSSLRootCertificates, Il2cppUtils::GetMethodPointer(
                "Assembly-CSharp.dll", "Solis.Common.Network", "Api", "GetSSLRootCertificates"));
        PS_ADD_HOOK(OctoSettings_get_Url, FindOctoUrlGetter());
    }
}
