package io.github.cylear.hoshimi.localify

import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import java.io.FileDescriptor
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
import java.util.concurrent.atomic.AtomicInteger
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
 *  1. [hookNameResolution] redirects DNS for the Firebase hosts (and the existing game hosts) to
 *     the private server's address. It hooks every Java layer a lookup can pass through:
 *     `InetAddress.getByName`/`getAllByName`, the hidden `getByNameOnNet`/`getAllByNameOnNet`
 *     implementations, `java.net.Inet6AddressImpl.lookupAllHostAddr` and
 *     `libcore.io.Linux`/`libcore.io.ForwardingOs.android_getaddrinfo`. The framework
 *     `okhttp`/`HttpsURLConnection` used by Firebase Auth does not necessarily call the public
 *     wrappers, which is why the lower layers matter. The returned `InetAddress` keeps the
 *     *googleapis* hostname (via `InetAddress.getByAddress(hostname, ...)`), so TLS SNI and
 *     Conscrypt's hostname verification still see the certificate's SAN.
 *  2. [hookSocketConnect] rewrites `<server address>:443` to `<server address>:<server port>` at
 *     `java.net.Socket.connect`, at `java.net.AbstractPlainSocketImpl.connect`, and at every
 *     `libcore.io.IoBridge`/`Linux`/`ForwardingOs` `connect`/`connectErrno` overload. The last layer
 *     is the one the framework `okhttp` path really lands in and it sees dual-stack
 *     (IPv4-mapped IPv6) addresses; the native `connect` hook does the same for libc sockets but is
 *     only installed in preserve-host mode (see `PrivateServer.cpp`), so Java sockets need their
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

    /** Upper bound for the "saw host:443 but did not rewrite it" diagnostic. */
    private const val MAX_CONNECT_MISS_LOGS = 10

    private val installed = AtomicBoolean(false)
    private val active = AtomicBoolean(false)
    private val connectMissLogCount = AtomicInteger()

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

    private val loggedTrustFailures = ConcurrentHashMap.newKeySet<String>()
    private val loggedErrors = ConcurrentHashMap.newKeySet<String>()

    /** Runtime class of `InetAddress[]`, shared by every DNS hook that returns an address list. */
    private val inetAddressArrayClass: Class<*> =
        java.lang.reflect.Array.newInstance(InetAddress::class.java, 0).javaClass

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
        hookNameResolution(classLoader)
        hookSocketConnect(classLoader)
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

    private fun hookNameResolution(classLoader: ClassLoader) {
        hookInetAddressMethods(classLoader)
        hookInet6AddressImpl(classLoader)
        hookLibcoreGetAddrInfo(classLoader, "libcore.io.Linux")
        hookLibcoreGetAddrInfo(classLoader, "libcore.io.ForwardingOs")
    }

    /**
     * Public/hidden `InetAddress` entry points. The public ones cover callers that resolve through
     * `getByName`/`getAllByName`; the hidden `*OnNet` variants are the actual implementation on
     * Android 7+ and are hooked as well, so a caller that skips the public wrapper (and the
     * `AddressCache` lookup inside it) still gets the redirect.
     */
    private fun hookInetAddressMethods(classLoader: ClassLoader) {
        val clazz = findClass("java.net.InetAddress", classLoader) ?: return
        var hooked = 0
        val intClass = Int::class.javaPrimitiveType
        for (method in clazz.declaredMethods) {
            val parameterTypes = method.parameterTypes
            if (parameterTypes.isEmpty() || parameterTypes[0] != String::class.java) continue
            val onNet = method.name == "getByNameOnNet" || method.name == "getAllByNameOnNet"
            if (onNet) {
                if (parameterTypes.size != 2 || parameterTypes[1] != intClass) continue
            }
            else if (parameterTypes.size != 1) {
                continue
            }

            val single: Boolean
            if (method.name == "getByName" || method.name == "getByNameOnNet") {
                if (method.returnType != InetAddress::class.java) continue
                single = true
            }
            else if (method.name == "getAllByName" || method.name == "getAllByNameOnNet") {
                if (method.returnType != inetAddressArrayClass) continue
                single = false
            }
            else {
                continue
            }

            if (method.name == "getByName") {
                getByNameMethod = method
            }
            if (hookMethod(method, nameLookupHook("InetAddress.${method.name}", single))) {
                hooked++
            }
        }
        if (hooked == 0) {
            Log.w(TAG, "PrivateServerRedirect: no InetAddress name-resolution method was hooked")
        }
    }

    /**
     * `Inet6AddressImpl.lookupAllHostAddr` is the native method every libcore name lookup ends in,
     * including the ones from the framework `okhttp`/`HttpsURLConnection` stack used by Firebase
     * Auth. The returned addresses keep the requested host name, so SNI and certificate hostname
     * verification still see the googleapis name. Every overload is hooked because the signature
     * gained a `netId` parameter over the years.
     */
    private fun hookInet6AddressImpl(classLoader: ClassLoader) {
        val clazz = findClass("java.net.Inet6AddressImpl", classLoader) ?: return
        var hooked = 0
        for (method in clazz.declaredMethods) {
            if (method.name != "lookupAllHostAddr") continue
            val parameterTypes = method.parameterTypes
            if (parameterTypes.isEmpty() || parameterTypes[0] != String::class.java) continue
            if (method.returnType != inetAddressArrayClass) continue
            if (hookMethod(method, nameLookupHook("Inet6AddressImpl.lookupAllHostAddr", single = false))) {
                hooked++
            }
        }
        if (hooked == 0) {
            Log.w(TAG, "PrivateServerRedirect: no Inet6AddressImpl.lookupAllHostAddr overload was hooked")
        }
    }

    /**
     * libcore's `Linux`/`ForwardingOs.android_getaddrinfo` is the Java-visible layer directly above
     * bionic's `android_getaddrinfofornet(3)`. Hooking it (plus the libc symbols on the native side)
     * covers every Android release, even when the concrete `Inet6AddressImpl` class changes.
     */
    private fun hookLibcoreGetAddrInfo(classLoader: ClassLoader, className: String) {
        val clazz = findClass(className, classLoader) ?: return
        var hooked = 0
        for (method in clazz.declaredMethods) {
            if (method.name != "android_getaddrinfo") continue
            val parameterTypes = method.parameterTypes
            if (parameterTypes.isEmpty() || parameterTypes[0] != String::class.java) continue
            if (method.returnType != inetAddressArrayClass) continue
            if (hookMethod(method, nameLookupHook("$className.android_getaddrinfo", single = false))) {
                hooked++
            }
        }
        if (hooked == 0) {
            Log.i(TAG, "PrivateServerRedirect: $className declares no hookable android_getaddrinfo")
        }
    }

    private fun nameLookupHook(label: String, single: Boolean): XC_MethodHook =
        object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                try {
                    val host = param.args.getOrNull(0) as? String ?: return
                    val rewritten = rewriteLookup(host, label) ?: return
                    param.setResult(if (single) rewritten[0] else rewritten)
                }
                catch (t: Throwable) {
                    Log.w(TAG, "PrivateServerRedirect: $label hook failed: ${failureText(t)}", t)
                }
            }
        }

    /** Returns the replacement address(es), or null when the lookup must be left alone. */
    private fun rewriteLookup(hostname: String, layer: String): Array<InetAddress>? {
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
        // Log every single lookup (not once per host) so the next device run shows which layer fires.
        Log.i(TAG, "PrivateServerRedirect: dns[$layer] redirect $hostname -> $serverHost:$serverPort")
        return arrayOf(mapped)
    }

    // ---- port ----------------------------------------------------------------------------

    private fun hookSocketConnect(classLoader: ClassLoader) {
        hookConnectOn(Socket::class.java)
        // On Android `Socket.connect` lands in `getImpl().connect(...)`, i.e. the package-private
        // `AbstractPlainSocketImpl.connect(SocketAddress, int)`. Hooking the impl covers Socket
        // subclasses whose `connect` never calls `super` (and okhttp's own socket factory output).
        hookConnectOn(loadClass("java.net.AbstractPlainSocketImpl", classLoader))
        // `HttpsURLConnection` (what Firebase Auth uses) wraps a plain `java.net.Socket`, which is
        // covered above. Conscrypt's SSLSocket implementations override `connect` and call their own
        // native connect, so hook them too when the build exposes them.
        for (name in listOf(
            "com.android.org.conscrypt.ConscryptFileDescriptorSocket",
            "com.android.org.conscrypt.ConscryptEngineSocket",
            "com.android.org.conscrypt.OpenSSLSocketImpl",
        )) {
            hookConnectOn(loadClass(name, classLoader))
        }
        // The layer that actually connects: `PlainSocketImpl` -> `Net.connect` ->
        // `IoBridge.connect(FileDescriptor, InetAddress, int)`. okhttp/Firebase reach these without
        // passing through a hookable Socket subclass, and this is also where dual-stack
        // (IPv4-mapped IPv6) addresses show up, so all three Os flavours are hooked.
        hookLibcoreConnect(classLoader, "libcore.io.IoBridge")
        hookLibcoreConnect(classLoader, "libcore.io.Linux")
        hookLibcoreConnect(classLoader, "libcore.io.ForwardingOs")
    }

    private fun loadClass(name: String, classLoader: ClassLoader): Class<*>? =
        try {
            Class.forName(name, false, classLoader)
        }
        catch (_: Throwable) {
            null
        }

    private fun hookConnectOn(clazz: Class<*>?) {
        if (clazz == null) return
        var hooked = 0
        for (method in connectMethods(clazz)) {
            if (hookMethod(method, connectHook)) {
                hooked++
            }
        }
        if (hooked == 0) {
            Log.i(TAG, "PrivateServerRedirect: ${clazz.name} declares no hookable connect(SocketAddress[, int])")
        }
        else {
            Log.i(TAG, "PrivateServerRedirect: port hook covered $clazz.name ($hooked method(s))")
        }
    }

    /** `connect` overloads from the class and its superclasses (Conscrypt subclasses override it). */
    private fun connectMethods(clazz: Class<*>): List<Method> {
        val methods = ArrayList<Method>()
        var current: Class<*>? = clazz
        while (current != null && current != Any::class.java) {
            for (method in current.declaredMethods) {
                if (method.name != "connect") continue
                val parameterTypes = method.parameterTypes
                if (parameterTypes.isEmpty() || parameterTypes[0] != SocketAddress::class.java) continue
                if (parameterTypes.size > 2) continue
                methods.add(method)
            }
            current = current.superclass
        }
        return methods
    }

    /**
     * Hooks `connect`/`connectErrno` on a `libcore.io` class. Every overload whose first three
     * parameters are `(FileDescriptor, InetAddress, int)` is covered, which includes the
     * `timeoutMs` variant and the `connectErrno` helper that the exception-translating wrappers use.
     */
    private fun hookLibcoreConnect(classLoader: ClassLoader, className: String) {
        val clazz = findClass(className, classLoader) ?: return
        var hooked = 0
        for (method in clazz.declaredMethods) {
            if (method.name != "connect" && method.name != "connectErrno") continue
            val parameterTypes = method.parameterTypes
            if (parameterTypes.size < 3 || parameterTypes.size > 4) continue
            if (parameterTypes[0] != FileDescriptor::class.java) continue
            if (parameterTypes[1] != InetAddress::class.java) continue
            if (parameterTypes[2] != Int::class.javaPrimitiveType) continue
            if (parameterTypes.size == 4 && parameterTypes[3] != Int::class.javaPrimitiveType) continue
            if (hookMethod(method, libcoreConnectHook)) {
                hooked++
            }
        }
        if (hooked > 0) {
            Log.i(TAG, "PrivateServerRedirect: hooked $hooked $className connect method(s)")
        }
        else {
            Log.w(
                TAG,
                "PrivateServerRedirect: $className declares no hookable " +
                        "connect(FileDescriptor,InetAddress,int[,int])"
            )
        }
    }

    private val connectHook = object : XC_MethodHook() {
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
                Log.w(TAG, "PrivateServerRedirect: Socket.connect hook failed: ${failureText(t)}", t)
            }
        }
    }

    /** `libcore.io` variants carry the port as a plain int argument (index 2), no SocketAddress. */
    private val libcoreConnectHook = object : XC_MethodHook() {
        override fun beforeHookedMethod(param: MethodHookParam) {
            try {
                val address = param.args.getOrNull(1) as? InetAddress ?: return
                val requestedPort = param.args.getOrNull(2) as? Int ?: return
                val targetPort = rewriteServerPort(address, requestedPort, "libcore") ?: return
                param.args[2] = targetPort
            }
            catch (t: Throwable) {
                Log.w(TAG, "PrivateServerRedirect: libcore connect hook failed: ${failureText(t)}", t)
            }
        }
    }

    /**
     * Returns a replacement [SocketAddress] when [requestedPort] is 443, the target is the private
     * server address, and the server listens on another port. The [InetAddress] instance is reused,
     * so its googleapis hostname (and therefore SNI) survives the rewrite.
     *
     * This is the path the framework `okhttp` takes for Firebase Auth: it resolves through our DNS
     * hook, builds `new InetSocketAddress(redirectedAddress, 443)` and calls
     * `Socket.connect(SocketAddress, timeout)` on a plain `java.net.Socket` before layering
     * `SSLSocket` on top.
     */
    private fun rewriteConnectTarget(target: SocketAddress, requestedPort: Int): SocketAddress? {
        val inet = target as? InetSocketAddress ?: return null
        if (!active.get() || requestedPort != DEFAULT_HTTPS_PORT) return null
        val targetPort = serverPort
        if (targetPort <= 0 || targetPort == DEFAULT_HTTPS_PORT) return null

        val targetAddress = inet.address
        if (targetAddress != null) {
            // Address comparison is byte based: Java sockets may hold the IPv4-mapped IPv6 form
            // (::ffff:a.b.c.d) of the same server while our redirect supplies an Inet4Address.
            val port = rewriteServerPort(targetAddress, requestedPort, "Socket.connect") ?: return null
            return try {
                InetSocketAddress(targetAddress, port)
            }
            catch (t: Throwable) {
                logErrorOnce("port:${targetAddress.hostAddress}", "cannot rewrite the connect target ${targetAddress.hostAddress}", t)
                null
            }
        }

        // Unresolved InetSocketAddress: the hostname identifies the request. Match the redirected
        // hosts and the server's own literal (which the DNS hook also returns for them).
        val host = normalizeHost(inet.hostString)
        if (host !in redirectHosts && host != normalizeHost(serverHost)) return null
        Log.i(TAG, "PrivateServerRedirect: port rewrite[Socket.connect,unresolved] $host:$requestedPort -> $serverHost:$targetPort")
        return InetSocketAddress(inet.hostString, targetPort)
    }

    /**
     * Port layer shared by the `Socket.connect` and `libcore.io` hooks: returns the private server
     * port when [address] designates the server and [requestedPort] is 443, else null.
     */
    private fun rewriteServerPort(address: InetAddress, requestedPort: Int, layer: String): Int? {
        if (!active.get() || requestedPort != DEFAULT_HTTPS_PORT) return null
        val targetPort = serverPort
        if (targetPort <= 0 || targetPort == DEFAULT_HTTPS_PORT) return null
        if (!isServerAddress(address)) {
            logConnectMiss(layer, address, requestedPort)
            return null
        }
        // Log every rewrite (not once per host): this is the line that proves the port layer fired.
        // hostAddress (not hostName) on purpose: hostName can trigger a reverse lookup in a hot path.
        Log.i(TAG, "PrivateServerRedirect: port rewrite[$layer] ${address.hostAddress}:$requestedPort -> $serverHost:$targetPort")
        return targetPort
    }

    /**
     * True when [address] designates the private server, either as a plain IPv4 address or as an
     * IPv4-mapped IPv6 address (`::ffff:a.b.c.d`), which is the form dual-stack Java sockets carry.
     */
    private fun isServerAddress(address: InetAddress): Boolean {
        val server = serverAddress() ?: return false
        val target = address.address
        val expected = server.address
        if (target.size == expected.size && target.contentEquals(expected)) return true
        return when {
            target.size == 16 && expected.size == 4 -> isV4MappedOf(target, expected)
            target.size == 4 && expected.size == 16 -> isV4MappedOf(expected, target)
            else -> false
        }
    }

    /** `mapped` is a 16-byte `::ffff:a.b.c.d` form of the 4-byte [v4] address. */
    private fun isV4MappedOf(mapped: ByteArray, v4: ByteArray): Boolean {
        if (mapped.size != 16 || v4.size != 4) return false
        for (index in 0 until 10) {
            if (mapped[index].toInt() != 0) return false
        }
        if ((mapped[10].toInt() and 0xff) != 0xff || (mapped[11].toInt() and 0xff) != 0xff) return false
        for (index in 0 until 4) {
            if (mapped[12 + index] != v4[index]) return false
        }
        return true
    }

    /**
     * Rate-limited diagnostic: shows which `host:443` targets the port hooks saw but did not
     * rewrite. Without it a silent non-match looks exactly like a hook that never ran.
     */
    private fun logConnectMiss(layer: String, address: InetAddress, port: Int) {
        val count = connectMissLogCount.incrementAndGet()
        if (count > MAX_CONNECT_MISS_LOGS) return
        Log.i(
            TAG,
            "PrivateServerRedirect: port skip[$layer] ${address.hostAddress}:$port " +
                    "does not match $serverHost:$serverPort"
        )
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
        val signatures = ArrayList<String>()
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
            if (hookMethod(method, trustHook)) {
                hooked++
                signatures.add(methodDescription(method))
            }
        }
        if (hooked > 0) {
            Log.i(
                TAG,
                "PrivateServerRedirect: hooked $hooked TrustManagerImpl method(s): " +
                        signatures.joinToString(", ")
            )
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
                // Log every fallback (not once per host): this proves the private-server CA was used.
                Log.i(
                    TAG,
                    "PrivateServerRedirect: trust fallback accepted ${chain.size} certificate(s) " +
                            "for ${host ?: "<unknown>"} using the private server CA"
                )
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

    private fun findClass(name: String, classLoader: ClassLoader): Class<*>? {
        return try {
            XposedHelpers.findClass(name, classLoader)
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerRedirect: cannot load $name: ${failureText(t)}", t)
            null
        }
    }

    private fun hookMethod(method: Method, hook: XC_MethodHook): Boolean {
        val description = methodDescription(method)
        return try {
            XposedBridge.hookMethod(method, hook)
            Log.i(TAG, "PrivateServerRedirect: hooked $description")
            true
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerRedirect: cannot hook $description: ${failureText(t)}", t)
            false
        }
    }

    private fun methodDescription(method: Method): String {
        val parameters = method.parameterTypes.joinToString(",") { it.name }
        return "${method.declaringClass.name}#${method.name}($parameters)"
    }

    private fun failureText(t: Throwable): String {
        val message = t.message
        return if (message.isNullOrBlank()) t.javaClass.name else "${t.javaClass.name}: $message"
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
