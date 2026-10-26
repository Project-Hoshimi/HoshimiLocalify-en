package io.github.cylear.hoshimi.localify

import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.security.GeneralSecurityException
import java.security.cert.CertPathValidator
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSession
import javax.net.ssl.X509TrustManager

/**
 * Java-side half of the private-server redirect.
 *
 * The native hooks in `app/src/main/cpp/HoshimiLocalify/PrivateServer.cpp` only see traffic that
 * goes through libc (`getaddrinfo`/`connect`) or through il2cpp (UnityWebRequest). Firebase Auth on
 * Android is the *Java* SDK (called over JNI from the Unity Firebase C++ SDK), so its DNS lookups
 * happen in `java.net.InetAddress` and its TLS handshakes use Conscrypt's
 * `com.android.org.conscrypt.TrustManagerImpl`. Neither is covered by the native hooks, therefore:
 *
 *  1. [hookNameResolution] redirects `InetAddress.getByName` / `getAllByName` for the Firebase
 *     hosts (and the existing game hosts) to the private server's address. The returned
 *     `InetAddress` keeps the *googleapis* hostname (via `InetAddress.getByAddress(hostname, ...)`),
 *     so TLS SNI and Conscrypt's hostname verification still see the certificate's SAN.
 *  2. [hookSocketConnect] rewrites `<server address>:443` to `<server address>:<server port>` at
 *     `java.net.Socket.connect`. The native `connect` hook does the same for libc sockets, but it
 *     is only installed in preserve-host mode (see `PrivateServer.cpp`), so Java sockets need their
 *     own rewrite to be independent of the native mode.
 *  3. [hookPlatformTrustManager] lets Conscrypt accept the private server's chain. Adding the CA to
 *     `getAcceptedIssuers()` (see [PrivateServerTrust]) does *not* make `checkServerTrusted` pass -
 *     that method only consults the system trust store. When the real implementation throws and the
 *     chain validates against the configured private-server CA, the call succeeds; anything that
 *     does not validate is rethrown unchanged. There is no accept-all path.
 *
 * Everything is inert until [onConfigChanged] delivers an enabled private-server configuration with
 * a usable URL; [PrivateServerTrust] owns that configuration, this object only mirrors it.
 */
object PrivateServerRedirect {
    /**
     * Hosts whose Java-side traffic is redirected while private-server mode is active. Keep in sync
     * with `g_redirectHosts` in `app/src/main/cpp/HoshimiLocalify/PrivateServer.cpp`.
     */
    private val BASE_REDIRECT_HOSTS = setOf(
        // Game API / master data, redirected by the native hooks as well.
        "api.game-idolypride.jp",
        "climaster.game-idolypride.jp",
        "api.octo-cloud.com",
        // Firebase Auth REST (Java SDK) and Google APIs reached from native code.
        "identitytoolkit.googleapis.com",
        "securetoken.googleapis.com",
        "www.googleapis.com",
    )

    private const val DEFAULT_HTTPS_PORT = 443
    private const val DEFAULT_HTTP_PORT = 80

    private val installed = AtomicBoolean(false)
    private val active = AtomicBoolean(false)

    private val redirectHosts: Set<String> = BASE_REDIRECT_HOSTS

    @Volatile
    private var serverHost: String = ""

    @Volatile
    private var serverPort: Int = 0

    @Volatile
    private var caTrustManager: X509TrustManager? = null

    private val serverAddress = AtomicReference<InetAddress?>(null)
    private val resolveLock = Any()
    private val resolving = ThreadLocal<Boolean>()

    /** Original `InetAddress.getByName(String)`, used to resolve the server without recursing. */
    @Volatile
    private var getByNameMethod: Method? = null

    private val loggedRedirects = ConcurrentHashMap.newKeySet<String>()
    private val loggedTrustFallbacks = ConcurrentHashMap.newKeySet<String>()
    private val loggedTrustFailures = ConcurrentHashMap.newKeySet<String>()
    private val loggedErrors = ConcurrentHashMap.newKeySet<String>()

    // ---- installation --------------------------------------------------------------------

    /**
     * Installs the hooks that are independent of the configuration, so they exist before Firebase
     * Auth (or anything else in the game process) touches DNS or TLS. Called from
     * [PrivateServerTrust.install].
     */
    fun install(classLoader: ClassLoader) {
        if (!installed.compareAndSet(false, true)) {
            return
        }
        hookNameResolution()
        hookSocketConnect()
        hookPlatformTrustManager(classLoader)
    }

    // ---- configuration -------------------------------------------------------------------

    /**
     * Mirrors the private-server configuration. [serverUrl] may be blank (a legacy CA cache only
     * carries the PEM); in that case TLS trust keeps working but no redirect is armed.
     */
    fun onConfigChanged(serverUrl: String, caCerts: List<X509Certificate>, source: String) {
        val endpoint = parseEndpoint(serverUrl)
        if (endpoint == null || caCerts.isEmpty()) {
            if (serverUrl.isNotBlank() && endpoint == null) {
                Log.w(
                    TAG,
                    "PrivateServerRedirect: cannot parse the private server URL from $source; " +
                            "Java DNS/port redirect stays off"
                )
            }
            onConfigCleared(source)
            return
        }
        val changed = endpoint.host != serverHost || endpoint.port != serverPort
        serverHost = endpoint.host
        serverPort = endpoint.port
        if (changed) {
            serverAddress.set(null)
        }
        caTrustManager = PrivateCaTrustManager(caCerts)
        active.set(true)
        if (changed) {
            Log.i(
                TAG,
                "PrivateServerRedirect: Java DNS redirect armed for " +
                        "${redirectHosts.size} host(s) -> ${endpoint.host}:${endpoint.port} " +
                        "(CA count=${caCerts.size}, $source)"
            )
        }
    }

    /** Drops every redirect/trust decision made for a previous configuration. */
    fun onConfigCleared(source: String) {
        if (active.compareAndSet(true, false)) {
            Log.i(TAG, "PrivateServerRedirect: Java redirect disabled ($source)")
        }
        serverHost = ""
        serverPort = 0
        caTrustManager = null
        serverAddress.set(null)
    }

    // ---- DNS -----------------------------------------------------------------------------

    private fun hookNameResolution() {
        val clazz = InetAddress::class.java
        val getByName = try {
            XposedHelpers.findMethodExact(clazz, "getByName", String::class.java)
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerRedirect: cannot find InetAddress.getByName(String)", t)
            null
        }
        val getAllByName = try {
            XposedHelpers.findMethodExact(clazz, "getAllByName", String::class.java)
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerRedirect: cannot find InetAddress.getAllByName(String)", t)
            null
        }
        getByNameMethod = getByName

        if (getByName != null) {
            try {
                XposedBridge.hookMethod(getByName, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            val host = param.args.getOrNull(0) as? String ?: return
                            val rewritten = rewriteLookup(host) ?: return
                            param.setResult(rewritten[0])
                        }
                        catch (t: Throwable) {
                            Log.w(TAG, "PrivateServerRedirect: getByName hook failed", t)
                        }
                    }
                })
                Log.i(TAG, "PrivateServerRedirect: hooked InetAddress.getByName")
            }
            catch (t: Throwable) {
                Log.w(TAG, "PrivateServerRedirect: cannot hook InetAddress.getByName", t)
            }
        }

        if (getAllByName != null) {
            try {
                XposedBridge.hookMethod(getAllByName, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            val host = param.args.getOrNull(0) as? String ?: return
                            val rewritten = rewriteLookup(host) ?: return
                            param.setResult(rewritten)
                        }
                        catch (t: Throwable) {
                            Log.w(TAG, "PrivateServerRedirect: getAllByName hook failed", t)
                        }
                    }
                })
                Log.i(TAG, "PrivateServerRedirect: hooked InetAddress.getAllByName")
            }
            catch (t: Throwable) {
                Log.w(TAG, "PrivateServerRedirect: cannot hook InetAddress.getAllByName", t)
            }
        }
    }

    /** Returns the replacement address(es), or null when the lookup must be left alone. */
    private fun rewriteLookup(hostname: String): Array<InetAddress>? {
        if (!active.get()) return null
        if (resolving.get() == true) return null
        val normalized = normalizeHost(hostname)
        if (normalized.isEmpty() || normalized !in redirectHosts) return null
        // InetAddress.getByAddress keeps the requested hostname on the instance, so Conscrypt uses
        // the googleapis host for SNI and for its hostname check against the certificate SANs.
        val address = serverAddress() ?: return null
        val mapped = try {
            InetAddress.getByAddress(hostname, address.address)
        }
        catch (t: Throwable) {
            logErrorOnce("dns:$normalized", "cannot build the redirected InetAddress for $hostname", t)
            return null
        }
        logRedirectOnce(normalized, "dns")
        return arrayOf(mapped)
    }

    // ---- port ----------------------------------------------------------------------------

    private fun hookSocketConnect() {
        hookConnectOn(Socket::class.java)
        // `HttpsURLConnection` (what Firebase Auth uses) wraps a plain `java.net.Socket`, which is
        // covered above. Conscrypt's SSLSocket implementations override `connect` and call their own
        // native connect, so hook them too when the build exposes them.
        for (name in listOf(
            "com.android.org.conscrypt.ConscryptFileDescriptorSocket",
            "com.android.org.conscrypt.ConscryptEngineSocket",
            "com.android.org.conscrypt.OpenSSLSocketImpl",
        )) {
            val clazz = try {
                Class.forName(name)
            }
            catch (_: Throwable) {
                null
            } ?: continue
            hookConnectOn(clazz)
        }
    }

    private fun hookConnectOn(clazz: Class<*>) {
        try {
            val hookCount = XposedBridge.hookAllMethods(clazz, "connect", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        val target = param.args.getOrNull(0) as? SocketAddress ?: return
                        val requestedPort = (param.args.getOrNull(1) as? Int)
                            ?: (target as? InetSocketAddress)?.port
                            ?: return
                        val rewritten = rewriteConnectTarget(target, requestedPort) ?: return
                        param.args[0] = rewritten
                    }
                    catch (t: Throwable) {
                        Log.w(TAG, "PrivateServerRedirect: Socket.connect hook failed", t)
                    }
                }
            })
            Log.i(TAG, "PrivateServerRedirect: hooked ${clazz.name}.connect ($hookCount method(s))")
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerRedirect: cannot hook ${clazz.name}.connect", t)
        }
    }

    /**
     * Returns a replacement [SocketAddress] when [requestedPort] is 443, the target is the private
     * server address, and the server listens on another port. The [InetAddress] instance is reused,
     * so its googleapis hostname (and therefore SNI) survives the rewrite.
     */
    private fun rewriteConnectTarget(target: SocketAddress, requestedPort: Int): SocketAddress? {
        if (!active.get()) return null
        if (requestedPort != DEFAULT_HTTPS_PORT) return null
        val targetPort = serverPort
        if (targetPort <= 0 || targetPort == DEFAULT_HTTPS_PORT) return null
        val inet = target as? InetSocketAddress ?: return null

        val targetAddress = inet.address
        val matches = if (targetAddress != null) {
            val server = serverAddress() ?: return null
            targetAddress == server
        }
        else {
            // Unresolved InetSocketAddress: the hostname identifies the request.
            normalizeHost(inet.hostString) in redirectHosts
        }
        if (!matches) return null

        val rewritten = try {
            if (targetAddress != null) InetSocketAddress(targetAddress, targetPort)
            else InetSocketAddress(inet.hostString, targetPort)
        }
        catch (t: Throwable) {
            logErrorOnce("port:${inet.hostString}", "cannot rewrite the connect target ${inet.hostString}", t)
            return null
        }
        logRedirectOnce(normalizeHost(inet.hostString), "port")
        return rewritten
    }

    // ---- TLS -----------------------------------------------------------------------------

    private fun hookPlatformTrustManager(classLoader: ClassLoader) {
        val clazz = try {
            XposedHelpers.findClass("com.android.org.conscrypt.TrustManagerImpl", classLoader)
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerRedirect: com.android.org.conscrypt.TrustManagerImpl not found", t)
            return
        }
        val chainArray = Array<X509Certificate>::class.java
        var hooked = 0
        for (method in clazz.declaredMethods) {
            val name = method.name
            if (name != "checkServerTrusted" && name != "checkTrusted") continue
            val parameterTypes = method.parameterTypes
            if (parameterTypes.size < 2) continue
            if (parameterTypes[0] != chainArray || parameterTypes[1] != String::class.java) continue
            // checkTrusted(..., boolean clientAuth): only the server-auth path is interesting.
            if (name == "checkTrusted" && parameterTypes.lastOrNull() == Boolean::class.javaPrimitiveType) {
                continue
            }
            try {
                XposedBridge.hookMethod(method, trustHook)
                hooked++
            }
            catch (t: Throwable) {
                Log.w(TAG, "PrivateServerRedirect: cannot hook TrustManagerImpl.$name", t)
            }
        }
        if (hooked > 0) {
            Log.i(TAG, "PrivateServerRedirect: hooked $hooked TrustManagerImpl.checkServerTrusted method(s)")
        }
        else {
            Log.w(TAG, "PrivateServerRedirect: no TrustManagerImpl.checkServerTrusted method was hooked")
        }
    }

    private val trustHook = object : XC_MethodHook() {
        override fun beforeHookedMethod(param: MethodHookParam) {
            val trustManager = caTrustManager
            if (trustManager == null || !active.get()) return
            val method = param.method as? Method ?: return
            val chain = (param.args.getOrNull(0) as? Array<*>)
                ?.filterIsInstance<X509Certificate>()
                ?: return
            if (chain.isEmpty()) return

            val originalResult = try {
                XposedBridge.invokeOriginalMethod(method, param.thisObject, param.args)
            }
            catch (t: Throwable) {
                val failure = unwrap(t)
                if (!isTrustFailure(failure)) {
                    param.setThrowable(failure)
                    return
                }
                val host = hostFromArgs(param.args)
                if (host != null && normalizeHost(host) !in redirectHosts) {
                    param.setThrowable(failure)
                    return
                }
                try {
                    trustManager.checkServerTrusted(chain.toTypedArray(), param.args[1] as String)
                }
                catch (fallbackFailure: Throwable) {
                    logTrustFailureOnce(host ?: "<unknown>", fallbackFailure)
                    param.setThrowable(failure)
                    return
                }
                param.setResult(resultFor(method, chain))
                logTrustFallbackOnce(host ?: "<unknown>", chain.size)
                return
            }
            // The original accepted the chain: skip the framework re-invocation.
            param.setResult(originalResult)
        }
    }

    /** Mirrors the return type of the hooked overload (void for the plain X509TrustManager one). */
    private fun resultFor(method: Method, chain: List<X509Certificate>): Any? {
        val returnType = method.returnType
        if (returnType == Void.TYPE) return null
        if (returnType.isAssignableFrom(ArrayList::class.java)) return ArrayList(chain)
        if (returnType.isAssignableFrom(Array<X509Certificate>::class.java)) return chain.toTypedArray()
        return ArrayList(chain)
    }

    private fun hostFromArgs(args: Array<Any?>?): String? {
        if (args == null) return null
        // 0 = chain, 1 = authType; anything after that may carry the host.
        for (index in 2 until args.size) {
            when (val arg = args[index]) {
                is String -> if (arg.isNotEmpty()) return arg
                is SSLSession -> arg.peerHost?.takeIf { it.isNotEmpty() }?.let { return it }
                is SSLEngine -> arg.peerHost?.takeIf { it.isNotEmpty() }?.let { return it }
                is Socket -> arg.inetAddress?.hostName?.takeIf { it.isNotEmpty() }?.let { return it }
                else -> Unit
            }
        }
        return null
    }

    private fun unwrap(t: Throwable): Throwable {
        if (t is InvocationTargetException) {
            return t.targetException ?: t
        }
        var current: Throwable = t
        var depth = 0
        while (current is InvocationTargetException && current.targetException != null && depth < 8) {
            current = current.targetException!!
            depth++
        }
        return current
    }

    private fun isTrustFailure(t: Throwable): Boolean {
        var current: Throwable? = t
        var depth = 0
        while (current != null && depth < 8) {
            if (current is CertificateException) return true
            current = current.cause
            depth++
        }
        return false
    }

    /**
     * PKIX validation against exactly the configured private-server CA certificates. No system trust
     * anchors are involved, so a chain that is not issued by that CA is always rejected.
     */
    private class PrivateCaTrustManager(caCerts: List<X509Certificate>) : X509TrustManager {
        private val anchors: Set<TrustAnchor> =
            caCerts.mapTo(LinkedHashSet()) { TrustAnchor(it, null) }
        private val acceptedIssuers: Array<X509Certificate> = caCerts.toTypedArray()

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            throw CertificateException("the private server CA does not trust client certificates")
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            if (chain.isNullOrEmpty()) {
                throw CertificateException("empty server certificate chain")
            }
            validate(chain)
        }

        fun validate(chain: Array<out X509Certificate>) {
            val factory = CertificateFactory.getInstance("X.509")
            // Conscrypt hands over the peer chain in TLS order (leaf first). Validate that order and,
            // as a tolerance for other call sites, the reversed one as well.
            var lastFailure: GeneralSecurityException? = null
            for (ordered in listOf(chain.toList(), chain.reversed())) {
                try {
                    val path = factory.generateCertPath(ordered)
                    val params = PKIXParameters(anchors).apply { isRevocationEnabled = false }
                    CertPathValidator.getInstance("PKIX").validate(path, params)
                    return
                }
                catch (e: GeneralSecurityException) {
                    lastFailure = e
                }
            }
            throw CertificateException(
                "certificate chain is not issued by the configured private server CA"
            ).also { it.initCause(lastFailure) }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = acceptedIssuers.copyOf()
    }

    // ---- helpers -------------------------------------------------------------------------

    private data class Endpoint(val host: String, val port: Int)

    private fun parseEndpoint(rawUrl: String): Endpoint? {
        val url = rawUrl.trim()
        val schemeEnd = url.indexOf("://")
        if (schemeEnd <= 0) return null
        val scheme = url.substring(0, schemeEnd).lowercase()
        if (scheme != "https" && scheme != "http") return null
        val authorityStart = schemeEnd + 3
        val slash = url.indexOf('/', authorityStart)
        var authority = url.substring(authorityStart, if (slash < 0) url.length else slash)
        val at = authority.lastIndexOf('@')
        if (at >= 0) authority = authority.substring(at + 1)
        if (authority.isEmpty()) return null

        val defaultPort = if (scheme == "https") DEFAULT_HTTPS_PORT else DEFAULT_HTTP_PORT
        val bracketEnd = authority.indexOf(']')
        val colon = authority.lastIndexOf(':')
        val host: String
        val port: Int
        if (colon < 0 || (bracketEnd in 0 until colon)) {
            host = authority
            port = defaultPort
        }
        else {
            host = authority.substring(0, colon)
            port = authority.substring(colon + 1).toIntOrNull() ?: return null
        }
        val normalizedHost = host.trim().removePrefix("[").removeSuffix("]")
        if (normalizedHost.isEmpty() || port !in 1..65535) return null
        return Endpoint(normalizedHost, port)
    }

    /** Resolves the private server through the *original* resolver, never through our own hook. */
    private fun serverAddress(): InetAddress? {
        serverAddress.get()?.let { return it }
        synchronized(resolveLock) {
            serverAddress.get()?.let { return it }
            val host = serverHost
            if (host.isEmpty()) return null
            if (resolving.get() == true) return null
            resolving.set(true)
            val resolved = try {
                val original = getByNameMethod
                if (original != null) {
                    XposedBridge.invokeOriginalMethod(original, null, arrayOf<Any?>(host)) as? InetAddress
                }
                else {
                    InetAddress.getByName(host)
                }
            }
            catch (t: Throwable) {
                logErrorOnce("resolve:$host", "cannot resolve the private server host $host", unwrap(t))
                null
            }
            finally {
                resolving.set(false)
            }
            if (resolved == null) return null
            serverAddress.set(resolved)
            return resolved
        }
    }

    private fun normalizeHost(value: String): String {
        var host = value.trim().lowercase()
        if (host.endsWith(".")) host = host.dropLast(1)
        return host
    }

    private fun logRedirectOnce(host: String, kind: String) {
        if (!loggedRedirects.add("$kind:$host")) return
        Log.i(
            TAG,
            "PrivateServerRedirect: $kind redirect $host -> $serverHost:$serverPort"
        )
    }

    private fun logTrustFallbackOnce(host: String, chainSize: Int) {
        if (!loggedTrustFallbacks.add(host)) return
        Log.i(
            TAG,
            "PrivateServerRedirect: trust fallback accepted $chainSize certificate(s) for $host " +
                    "using the private server CA"
        )
    }

    private fun logTrustFailureOnce(host: String, failure: Throwable) {
        if (!loggedTrustFailures.add(host)) return
        Log.w(
            TAG,
            "PrivateServerRedirect: trust fallback rejected the chain for $host; " +
                    "rethrowing the platform verdict",
            failure
        )
    }

    private fun logErrorOnce(key: String, message: String, failure: Throwable) {
        if (!loggedErrors.add(key)) return
        Log.w(TAG, "PrivateServerRedirect: $message", failure)
    }
}
