package io.github.cylear.hoshimi.localify

import android.app.Activity
import android.app.AndroidAppHelper
import android.content.Context
import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import io.github.cylear.hoshimi.localify.models.IdolyprideConfig
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.io.File
import java.lang.reflect.Method
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.X509TrustManager

/**
 * Adds the private server CA to the trust anchors that libunity.so reports to UnityTLS.
 *
 * libunity.so builds the root list for UnityWebRequest inside libcurl/UnityTLS over JNI (verified
 * against the shipping binary, see the JNI strings below):
 *
 *   KeyStore.getInstance("AndroidCAStore").load((LoadStoreParameter) null)
 *     -> TrustManagerFactory.getInstance(<algorithm>).init(keyStore)
 *     -> TrustManagerFactory.getTrustManagers()
 *     -> ((X509TrustManager) tm).getAcceptedIssuers()
 *     -> X509Certificate.getEncoded() for every entry
 *
 * UnityTLS then treats those encodings as its own trust anchors, so the certificate chain of our
 * private server is accepted without the CA being present in the Android system store (which we
 * cannot write to on an unrooted, LSPatch-patched device).
 *
 * We only *append* certificates to the array returned by getAcceptedIssuers(). That array does not
 * take part in the validation decisions of conscrypt, so java.net / OkHttp / every other consumer
 * keeps validating exactly as before; nothing is accepted that was not accepted before, and there
 * is no accept-all path here.
 */
object PrivateServerTrust {
    private const val CACHE_FILE_NAME = "hoshimi-private-server-ca.pem"
    private const val REQUEST_CONFIG_MARKER = "requestConfig"
    private const val AUGMENT_LOG_INTERVAL_MS = 2000L

    /** Lenient on purpose: a config written by a newer/older module build must never break trust. */
    private val configJson = Json { ignoreUnknownKeys = true }
    private val pemBlockRegex = Regex(
        "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----"
    )

    private val installed = AtomicBoolean(false)
    private val hookedAcceptedIssuersMethods = ConcurrentHashMap.newKeySet<Method>()
    private val classesWithoutAcceptedIssuers = ConcurrentHashMap.newKeySet<Class<*>>()

    @Volatile
    private var caCerts: List<X509Certificate> = emptyList()

    @Volatile
    private var cacheFileRead = false

    @Volatile
    private var lastAugmentLogAt = 0L

    /**
     * Installs the hooks that are independent of the configuration. Must be called from
     * handleLoadPackage(), i.e. before anything in the game process can touch TLS.
     */
    fun install(classLoader: ClassLoader) {
        if (!installed.compareAndSet(false, true)) {
            return
        }
        hookTrustManagerFactory(classLoader)
        hookActivityLaunch(classLoader)
    }

    /** Feeds the configuration carried by the launch intent, before the Unity player exists. */
    fun observeIntent(activity: Activity?) {
        if (activity == null) {
            return
        }
        val raw = try {
            activity.intent?.getStringExtra("iprData")
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: cannot read the launch intent", t)
            null
        }
        if (raw.isNullOrBlank()) {
            // Launched straight from the launcher: fall back to the CA cached by a previous start.
            ensureCachedCaLoaded()
            return
        }
        observeConfigJson(raw, "intent/${activity.javaClass.simpleName}")
    }

    /** Feeds an already received `iprData` JSON payload or parsed configuration. */
    fun observeConfigJson(raw: String?, source: String) {
        if (raw.isNullOrBlank() || raw == REQUEST_CONFIG_MARKER) {
            ensureCachedCaLoaded()
            return
        }
        val config = try {
            configJson.decodeFromString<IdolyprideConfig>(raw)
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: cannot parse the config from $source", t)
            return
        }
        observeConfig(config, source)
    }

    fun observeConfig(config: IdolyprideConfig?, source: String) {
        if (config == null) {
            return
        }
        applyConfig(config.privateServerEnabled, config.privateServerCaPem, source, appContext())
    }

    // ---- hooks ---------------------------------------------------------------------------

    /**
     * Unity resolves the root list through TrustManagerFactory, so this is the narrowest reliable
     * point: it tells us the concrete X509TrustManager classes that Unity is about to ask, and we
     * hook getAcceptedIssuers on each of them exactly once.
     */
    private fun hookTrustManagerFactory(classLoader: ClassLoader) {
        try {
            val factoryClass = XposedHelpers.findClass("javax.net.ssl.TrustManagerFactory", classLoader)
            val hookCount = XposedBridge.hookAllMethods(factoryClass, "getTrustManagers", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    try {
                        // Oldest hook point that can still see a cached CA on a direct launch.
                        ensureCachedCaLoaded()

                        val managers = param.result as? Array<*> ?: return
                        var hooked = 0
                        var trustManagers = 0
                        for (manager in managers) {
                            if (manager !is X509TrustManager) {
                                continue
                            }
                            trustManagers++
                            if (hookAcceptedIssuers(manager.javaClass)) {
                                hooked++
                            }
                        }
                        Log.i(
                            TAG,
                            "PrivateServerTrust: TrustManagerFactory.getTrustManagers -> " +
                                    "$trustManagers X509TrustManager(s), newly hooked $hooked, " +
                                    "caCerts=${caCerts.size}"
                        )
                    }
                    catch (t: Throwable) {
                        Log.w(TAG, "PrivateServerTrust: getTrustManagers hook failed", t)
                    }
                }
            })
            Log.i(TAG, "PrivateServerTrust: hooked TrustManagerFactory.getTrustManagers ($hookCount method(s))")
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: cannot hook TrustManagerFactory.getTrustManagers", t)
        }
    }

    /**
     * The configuration reaches the game process as an Intent extra, so the earliest point where
     * the PEM is readable is right before the Unity activity is created (callActivityOnCreate runs
     * before onCreate, and therefore before UnityPlayer starts the runtime and its networking).
     */
    private fun hookActivityLaunch(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "android.app.Instrumentation",
                classLoader,
                "callActivityOnCreate",
                Activity::class.java,
                Bundle::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            observeIntent(param.args[0] as? Activity)
                        }
                        catch (t: Throwable) {
                            Log.w(TAG, "PrivateServerTrust: intent pickup failed", t)
                        }
                    }
                }
            )
            Log.i(TAG, "PrivateServerTrust: hooked Instrumentation.callActivityOnCreate for early CA pickup")
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: cannot hook Instrumentation.callActivityOnCreate", t)
        }
    }

    /** Returns true only when a new getAcceptedIssuers() implementation was hooked. */
    private fun hookAcceptedIssuers(trustManagerClass: Class<*>): Boolean {
        val method = findAcceptedIssuersMethod(trustManagerClass)
        if (method == null) {
            if (classesWithoutAcceptedIssuers.add(trustManagerClass)) {
                Log.w(
                    TAG,
                    "PrivateServerTrust: ${trustManagerClass.name} exposes no getAcceptedIssuers()"
                )
            }
            return false
        }
        if (!hookedAcceptedIssuersMethods.add(method)) {
            return false
        }
        return try {
            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    try {
                        augmentAcceptedIssuers(param)
                    }
                    catch (t: Throwable) {
                        Log.w(TAG, "PrivateServerTrust: getAcceptedIssuers hook failed", t)
                    }
                }
            })
            Log.i(
                TAG,
                "PrivateServerTrust: hooked X509TrustManager.getAcceptedIssuers on " +
                        "${trustManagerClass.name} (declared by ${method.declaringClass?.name})"
            )
            true
        }
        catch (t: Throwable) {
            Log.w(
                TAG,
                "PrivateServerTrust: cannot hook getAcceptedIssuers on ${trustManagerClass.name}", t
            )
            false
        }
    }

    private fun findAcceptedIssuersMethod(clazz: Class<*>): Method? {
        var current: Class<*>? = clazz
        while (current != null && current != Any::class.java) {
            val found = try {
                current.getDeclaredMethod("getAcceptedIssuers")
            }
            catch (_: Throwable) {
                null
            }
            if (found != null) {
                return found
            }
            current = current.superclass
        }
        return null
    }

    private fun augmentAcceptedIssuers(param: XC_MethodHook.MethodHookParam) {
        val certs = caCerts
        if (certs.isEmpty()) {
            return
        }
        val current = (param.result as? Array<*>)?.filterIsInstance<X509Certificate>() ?: return
        val missing = certs.filter { ours -> current.none { it.encoded.contentEquals(ours.encoded) } }
        if (missing.isEmpty()) {
            return
        }
        val merged = (current + missing).toTypedArray()
        param.result = merged
        logAugmented(param.thisObject?.javaClass?.name ?: "unknown", current.size, merged.size)
    }

    private fun logAugmented(className: String, before: Int, after: Int) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastAugmentLogAt < AUGMENT_LOG_INTERVAL_MS) {
            return
        }
        lastAugmentLogAt = now
        Log.i(
            TAG,
            "PrivateServerTrust: getAcceptedIssuers on $className augmented $before -> $after"
        )
    }

    // ---- configuration -------------------------------------------------------------------

    private fun applyConfig(enabled: Boolean, pem: String, source: String, context: Context?) {
        if (!enabled || pem.isBlank()) {
            if (caCerts.isNotEmpty()) {
                caCerts = emptyList()
                Log.i(TAG, "PrivateServerTrust: private server CA removed ($source)")
            }
            deleteCachedCa(context)
            return
        }

        val parsed = parseCerts(pem)
        if (parsed.isEmpty()) {
            Log.e(TAG, "PrivateServerTrust: no X.509 certificate in the configured CA PEM ($source)")
            return
        }
        if (sameCerts(parsed, caCerts)) {
            return
        }

        caCerts = parsed
        Log.i(
            TAG,
            "PrivateServerTrust: private server CA loaded from $source: count=${parsed.size}, " +
                    "subjects=[${parsed.joinToString { it.subjectX500Principal.name }}]"
        )
        writeCachedCa(context, pem)
    }

    private fun parseCerts(pem: String): List<X509Certificate> {
        return try {
            val factory = CertificateFactory.getInstance("X.509")
            val blocks = pemBlockRegex.findAll(pem).map { it.value }.toList()
            if (blocks.isEmpty()) {
                // Tolerate a bare base64 body without the BEGIN/END armour.
                val wrapped = "-----BEGIN CERTIFICATE-----\n$pem\n-----END CERTIFICATE-----"
                return listOfNotNull(decodeCert(factory, wrapped))
            }
            blocks.mapNotNull { decodeCert(factory, it) }
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: CA PEM parsing failed", t)
            emptyList()
        }
    }

    private fun decodeCert(factory: CertificateFactory, block: String): X509Certificate? {
        return try {
            factory.generateCertificate(
                ByteArrayInputStream(block.toByteArray(Charsets.US_ASCII))
            ) as? X509Certificate
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: skipping an unparsable PEM block", t)
            null
        }
    }

    private fun sameCerts(a: List<X509Certificate>, b: List<X509Certificate>): Boolean {
        if (a.size != b.size) {
            return false
        }
        val bEncoded = b.map { it.encoded }
        return a.all { aCert -> bEncoded.any { it.contentEquals(aCert.encoded) } }
    }

    // ---- cache ---------------------------------------------------------------------------

    /**
     * Launching the game straight from the launcher carries no `iprData` extra, so the CA seen on a
     * previous (module initiated) launch is cached in the game's own files directory. Only the game
     * process can read or write it, which is exactly what LSPatch integrated mode needs.
     */
    private fun ensureCachedCaLoaded() {
        if (cacheFileRead) {
            return
        }
        cacheFileRead = true
        if (caCerts.isNotEmpty()) {
            return
        }
        val context = appContext()
        if (context == null) {
            cacheFileRead = false
            return
        }
        val file = File(context.filesDir, CACHE_FILE_NAME)
        val pem = try {
            if (file.isFile) file.readText() else null
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: cannot read the cached CA", t)
            null
        }
        if (pem.isNullOrBlank()) {
            return
        }
        Log.i(TAG, "PrivateServerTrust: using the CA cached at ${file.absolutePath}")
        applyConfig(true, pem, "cache", context)
    }

    private fun writeCachedCa(context: Context?, pem: String) {
        val ctx = context ?: return
        try {
            val file = File(ctx.filesDir, CACHE_FILE_NAME)
            if (file.isFile && file.readText() == pem) {
                return
            }
            file.writeText(pem)
            Log.i(TAG, "PrivateServerTrust: cached the CA for the next launch (${file.absolutePath})")
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: cannot cache the CA", t)
        }
    }

    private fun deleteCachedCa(context: Context?) {
        val ctx = context ?: return
        try {
            val file = File(ctx.filesDir, CACHE_FILE_NAME)
            if (file.isFile && file.delete()) {
                Log.i(TAG, "PrivateServerTrust: removed the cached CA")
            }
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: cannot remove the cached CA", t)
        }
    }

    private fun appContext(): Context? {
        return try {
            AndroidAppHelper.currentApplication()
        }
        catch (t: Throwable) {
            Log.w(TAG, "PrivateServerTrust: no application context available", t)
            null
        }
    }
}
