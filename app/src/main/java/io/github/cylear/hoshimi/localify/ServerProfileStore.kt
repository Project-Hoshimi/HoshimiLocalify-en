package io.github.cylear.hoshimi.localify

import android.app.Activity
import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.os.Process
import android.util.Log
import io.github.cylear.hoshimi.localify.models.IdolyprideConfig
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

/**
 * A server the player can point the game at.
 *
 * Stored in `<game dataDir>/files/hoshimi-profiles/profiles.json` as a plain JSON list. The
 * official profile (id [ServerProfile.OFFICIAL_ID]) always exists; private profiles carry the CA
 * that the game has to trust for that server.
 */
@Serializable
data class ServerProfile(
    val id: String,
    val kind: String = KIND_PRIVATE,
    val url: String = "",
    val caPem: String = "",
    val caSha256: String = "",
    val label: String = "",
) {
    companion object {
        const val KIND_OFFICIAL = "official"
        const val KIND_PRIVATE = "private"
        const val OFFICIAL_ID = "official"
    }
}

@Serializable
private data class ActiveProfileFile(val activeId: String)

@Serializable
private data class PendingProfileFile(val targetId: String)

/**
 * In-game server selection state, shared by the game process only.
 *
 * The files live inside the game's own sandbox (`files/hoshimi-profiles/`) because the companion
 * module app is usually not installed when the module is embedded with LSPatch:
 *
 *  - `profiles.json` - every known server, official first;
 *  - `active.json`   - `{activeId}` of the profile the game should use;
 *  - `pending.json`  - written right before a relaunch and consumed at the next process start,
 *                      when the per-server account files are swapped.
 *
 * Every account-specific file (Firebase auth store, player prefs, the Octo user directory) is
 * filed under `<profile>/account/` while that profile is *not* active, and moved back into place
 * when it becomes active again. Asset/master caches are deliberately shared.
 */
object ServerProfileStore {
    private const val FILE_PROFILES = "profiles.json"
    private const val FILE_ACTIVE = "active.json"
    private const val FILE_PENDING = "pending.json"

    private const val PROFILE_DIR_NAME = "hoshimi-profiles"
    private const val ACCOUNT_DIR_NAME = "account"

    private const val LEGACY_CA_CACHE = "hoshimi-private-server-ca.pem"
    private const val LEGACY_ENABLED_PREFIX = "# enabled="
    private const val LEGACY_SAVED_AT_PREFIX = "# savedAt="
    private const val LEGACY_URL_PREFIX = "# url="

    private const val PLAYER_PREFS_PATH = "shared_prefs/game.qualiarts.idolypride.v2.playerprefs.xml"
    private const val FIREBASE_STORE_DIR = "shared_prefs"
    private const val FIREBASE_STORE_PREFIX = "com.google.firebase.auth.api.Store."
    private const val OCTO_USER_DIR = "files/octo/user"

    private const val DEFAULT_HTTPS_PORT = 443
    private const val DEFAULT_HTTP_PORT = 80

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = true
    }
    private val profileListSerializer = ListSerializer(ServerProfile.serializer())

    /** Synchronises this object's file access; every entry point may run on any thread. */
    private val lock = Any()

    /**
     * True when the companion module app answered `requestConfig` with private server enabled. The
     * switch button then refuses to change anything and only explains who owns the configuration.
     */
    @Volatile
    var appManagedPrivateServer: Boolean = false
        private set

    fun updateAppManaged(enabled: Boolean) {
        appManagedPrivateServer = enabled
    }

    // ---- locations -----------------------------------------------------------------------

    fun profilesDir(filesDir: File): File = File(filesDir, PROFILE_DIR_NAME)

    fun profilesDirForDataDir(dataDir: File): File = profilesDir(File(dataDir, "files"))

    fun accountDir(filesDir: File, profileId: String): File =
        File(File(profilesDir(filesDir), profileId), ACCOUNT_DIR_NAME)

    fun officialProfile(): ServerProfile = ServerProfile(
        id = ServerProfile.OFFICIAL_ID,
        kind = ServerProfile.KIND_OFFICIAL,
        url = "",
        caPem = "",
        caSha256 = "",
        label = "Official server"
    )

    // ---- profiles ------------------------------------------------------------------------

    /** Reads `profiles.json`, repairing a missing/malformed file. The result always has official. */
    fun loadProfiles(filesDir: File): List<ServerProfile> {
        synchronized(lock) {
            return loadProfilesLocked(filesDir)
        }
    }

    private fun loadProfilesLocked(filesDir: File): List<ServerProfile> {
        val dir = profilesDir(filesDir)
        val file = File(dir, FILE_PROFILES)
        val parsed = try {
            if (file.isFile) {
                json.decodeFromString(profileListSerializer, file.readText())
            }
            else {
                emptyList()
            }
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerProfileStore: cannot read ${file.absolutePath}; rebuilding", t)
            emptyList()
        }
        val result = ArrayList<ServerProfile>(parsed.size + 1)
        result.add(parsed.firstOrNull { it.id == ServerProfile.OFFICIAL_ID } ?: officialProfile())
        for (profile in parsed) {
            if (profile.id == ServerProfile.OFFICIAL_ID) continue
            if (result.any { it.id == profile.id }) continue
            result.add(profile)
        }
        if (result.size != parsed.size || result.firstOrNull()?.kind != ServerProfile.KIND_OFFICIAL) {
            saveProfilesLocked(filesDir, result)
        }
        return result
    }

    private fun saveProfilesLocked(filesDir: File, profiles: List<ServerProfile>) {
        try {
            val dir = profilesDir(filesDir)
            dir.mkdirs()
            val file = File(dir, FILE_PROFILES)
            file.writeText(json.encodeToString(profileListSerializer, profiles))
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerProfileStore: cannot write profiles.json", t)
        }
    }

    fun saveProfiles(filesDir: File, profiles: List<ServerProfile>) {
        synchronized(lock) {
            saveProfilesLocked(filesDir, profiles)
        }
    }

    /** Adds [profile] or replaces the entry with the same id. */
    fun upsertProfile(filesDir: File, profile: ServerProfile) {
        synchronized(lock) {
            val profiles = ArrayList(loadProfilesLocked(filesDir))
            val index = profiles.indexOfFirst { it.id == profile.id }
            if (index >= 0) {
                profiles[index] = profile
            }
            else {
                profiles.add(profile)
            }
            saveProfilesLocked(filesDir, profiles)
        }
    }

    // ---- active / pending ----------------------------------------------------------------

    fun readActiveId(filesDir: File): String? {
        synchronized(lock) {
            return readActiveIdLocked(filesDir)
        }
    }

    private fun readActiveIdLocked(filesDir: File): String? {
        val file = File(profilesDir(filesDir), FILE_ACTIVE)
        return try {
            if (!file.isFile) return null
            json.decodeFromString(ActiveProfileFile.serializer(), file.readText()).activeId
                .takeIf { it.isNotBlank() }
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerProfileStore: cannot read active.json", t)
            null
        }
    }

    fun writeActiveId(filesDir: File, profileId: String) {
        synchronized(lock) {
            writeActiveIdLocked(filesDir, profileId)
        }
    }

    private fun writeActiveIdLocked(filesDir: File, profileId: String) {
        try {
            val dir = profilesDir(filesDir)
            dir.mkdirs()
            File(dir, FILE_ACTIVE).writeText(
                json.encodeToString(ActiveProfileFile.serializer(), ActiveProfileFile(profileId))
            )
            Log.i(TAG, "ServerProfileStore: active profile -> $profileId")
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerProfileStore: cannot write active.json", t)
        }
    }

    fun readPendingTarget(filesDir: File): String? {
        synchronized(lock) {
            val file = File(profilesDir(filesDir), FILE_PENDING)
            return try {
                if (!file.isFile) return null
                json.decodeFromString(PendingProfileFile.serializer(), file.readText()).targetId
                    .takeIf { it.isNotBlank() }
            }
            catch (t: Throwable) {
                Log.w(TAG, "ServerProfileStore: cannot read pending.json", t)
                null
            }
        }
    }

    fun writePendingTarget(filesDir: File, targetId: String) {
        synchronized(lock) {
            try {
                val dir = profilesDir(filesDir)
                dir.mkdirs()
                File(dir, FILE_PENDING).writeText(
                    json.encodeToString(PendingProfileFile.serializer(), PendingProfileFile(targetId))
                )
                Log.i(TAG, "ServerProfileStore: pending switch -> $targetId")
            }
            catch (t: Throwable) {
                Log.w(TAG, "ServerProfileStore: cannot write pending.json", t)
            }
        }
    }

    fun deletePending(filesDir: File) {
        synchronized(lock) {
            val file = File(profilesDir(filesDir), FILE_PENDING)
            try {
                if (file.isFile) {
                    file.delete()
                    Log.i(TAG, "ServerProfileStore: pending switch cleared")
                }
            }
            catch (t: Throwable) {
                Log.w(TAG, "ServerProfileStore: cannot delete pending.json", t)
            }
        }
    }

    // ---- effective configuration ---------------------------------------------------------

    /**
     * The private profile selected by `active.json`, or null when the active server is official
     * (or the id is unknown, which is treated as official).
     */
    fun activePrivateProfile(filesDir: File): ServerProfile? {
        synchronized(lock) {
            val activeId = readActiveIdLocked(filesDir) ?: return null
            if (activeId == ServerProfile.OFFICIAL_ID) return null
            return loadProfilesLocked(filesDir).firstOrNull {
                it.id == activeId && it.kind == ServerProfile.KIND_PRIVATE && it.url.isNotBlank()
            }
        }
    }

    /** Copies the active profile's private-server fields onto [config]. */
    fun applyActiveProfile(config: IdolyprideConfig, filesDir: File): IdolyprideConfig {
        val profile = activePrivateProfile(filesDir)
        if (profile != null) {
            config.privateServerEnabled = true
            config.privateServerUrl = profile.url
            config.privateServerCaPem = profile.caPem
        }
        else {
            config.privateServerEnabled = false
            config.privateServerUrl = ""
            config.privateServerCaPem = ""
        }
        return config
    }

    // ---- lifecycle (call from handleLoadPackage) -----------------------------------------

    /**
     * Creates `active.json` on the very first start. When a legacy enabled CA cache exists (the
     * pre-profile way a private server was configured), its server becomes a profile and is made
     * active, exactly like the previous build would have trusted it.
     */
    fun ensureInitialized(dataDir: File): String {
        synchronized(lock) {
            val filesDir = File(dataDir, "files")
            profilesDir(filesDir).mkdirs()
            loadProfilesLocked(filesDir)
            val existing = readActiveIdLocked(filesDir)
            if (existing != null) return existing

            migrateLegacyCacheLocked(filesDir)?.let { return it }
            writeActiveIdLocked(filesDir, ServerProfile.OFFICIAL_ID)
            Log.i(TAG, "ServerProfileStore: first start, active profile is official")
            return ServerProfile.OFFICIAL_ID
        }
    }

    /**
     * Migration used at process start: when there is still no `active.json` and the previous build
     * left an enabled CA cache, that server becomes a profile and the active one. Returns the id it
     * made active, or null when there was nothing to migrate (the caller then leaves `active.json`
     * absent so the first-launch prompt can run).
     */
    fun migrateLegacyCacheIfPresent(dataDir: File): String? {
        synchronized(lock) {
            val filesDir = File(dataDir, "files")
            profilesDir(filesDir).mkdirs()
            loadProfilesLocked(filesDir)
            if (readActiveIdLocked(filesDir) != null) return null
            return migrateLegacyCacheLocked(filesDir)
        }
    }

    private fun migrateLegacyCacheLocked(filesDir: File): String? {
        val legacy = readLegacyCachedCa(File(filesDir, LEGACY_CA_CACHE)) ?: return null
        if (!legacy.enabled || legacy.url.isBlank() || legacy.pem.isBlank()) return null
        val profile = buildPrivateProfile(legacy.url, legacy.pem) ?: return null
        val profiles = ArrayList(loadProfilesLocked(filesDir))
        val index = profiles.indexOfFirst { it.id == profile.id }
        if (index >= 0) profiles[index] = profile else profiles.add(profile)
        saveProfilesLocked(filesDir, profiles)
        writeActiveIdLocked(filesDir, profile.id)
        Log.i(
            TAG,
            "ServerProfileStore: migrated the legacy cached CA of ${profile.url} " +
                    "into profile ${profile.id}"
        )
        return profile.id
    }

    /** Creates a private profile from a configuration the module app supplied (migration only). */
    fun migrateFromAppConfig(filesDir: File, config: IdolyprideConfig?) {
        if (config == null || !config.privateServerEnabled || config.privateServerUrl.isBlank()) return
        synchronized(lock) {
            profilesDir(filesDir).mkdirs()
            loadProfilesLocked(filesDir)
            if (readActiveIdLocked(filesDir) != null) return
            val profile = buildPrivateProfile(config.privateServerUrl, config.privateServerCaPem)
            if (profile == null) return
            val profiles = ArrayList(loadProfilesLocked(filesDir))
            val index = profiles.indexOfFirst { it.id == profile.id }
            if (index >= 0) profiles[index] = profile else profiles.add(profile)
            saveProfilesLocked(filesDir, profiles)
            writeActiveIdLocked(filesDir, profile.id)
            Log.i(TAG, "ServerProfileStore: migrated the module app configuration into ${profile.id}")
        }
    }

    /**
     * Consumes `pending.json`: files the active server's account, restores the target server's
     * account, then flips `active.json`. Runs before Firebase's ContentProvider in the new process,
     * so no component can read a token that belongs to the previous server.
     */
    fun swapPendingAccount(dataDir: File) {
        val filesDir = File(dataDir, "files")
        val targetId = readPendingTarget(filesDir) ?: return
        try {
            val activeId = ensureInitialized(dataDir)
            if (activeId == targetId) {
                Log.i(TAG, "ServerProfileStore: pending target $targetId is already active; nothing to swap")
                deletePending(filesDir)
                return
            }
            Log.i(TAG, "ServerProfileStore: swapping account files $activeId -> $targetId")
            saveAccountFiles(dataDir, filesDir, activeId)
            restoreAccountFiles(dataDir, filesDir, targetId)
            writeActiveId(filesDir, targetId)
            deletePending(filesDir)
            Log.i(TAG, "ServerProfileStore: server switch to $targetId complete")
        }
        catch (t: Throwable) {
            // Files are left as they are on purpose: a half-swapped account is worse than a retry.
            Log.e(TAG, "ServerProfileStore: account swap to $targetId failed; keeping $targetId pending", t)
            deletePending(filesDir)
        }
    }

    // ---- account files -------------------------------------------------------------------

    /** Relative paths of every file that belongs to the login of one server. */
    private fun accountEntries(dataDir: File): List<File> {
        val entries = ArrayList<File>(4)
        val sharedPrefs = File(dataDir, FIREBASE_STORE_DIR)
        val firebase = sharedPrefs.listFiles()
            ?.filter { it.isFile && it.name.startsWith(FIREBASE_STORE_PREFIX) && it.name.endsWith(".xml") }
            ?.sortedBy { it.name }
        if (firebase != null) entries.addAll(firebase)
        File(dataDir, PLAYER_PREFS_PATH).takeIf { it.exists() }?.let { entries.add(it) }
        File(dataDir, OCTO_USER_DIR).takeIf { it.exists() }?.let { entries.add(it) }
        return entries
    }

    private fun saveAccountFiles(dataDir: File, filesDir: File, profileId: String) {
        val account = accountDir(filesDir, profileId)
        deleteRecursively(account)
        account.mkdirs()
        for (entry in accountEntries(dataDir)) {
            val relative = entry.relativeTo(dataDir).path
            val destination = File(account, relative)
            destination.parentFile?.mkdirs()
            Log.i(TAG, "ServerProfileStore: stashing $relative for $profileId")
            move(entry, destination)
        }
    }

    private fun restoreAccountFiles(dataDir: File, filesDir: File, profileId: String) {
        val account = accountDir(filesDir, profileId)
        if (!account.isDirectory) {
            Log.i(TAG, "ServerProfileStore: no saved account for $profileId; the game will create one")
            return
        }
        val sharedPrefs = File(account, FIREBASE_STORE_DIR)
        sharedPrefs.listFiles()?.sortedBy { it.name }?.forEach { source ->
            if (!source.isFile) return@forEach
            val relative = source.relativeTo(account).path
            val destination = File(dataDir, relative)
            destination.parentFile?.mkdirs()
            Log.i(TAG, "ServerProfileStore: restoring $relative for $profileId")
            move(source, destination)
        }
        val userDir = File(account, OCTO_USER_DIR)
        if (userDir.exists()) {
            val destination = File(dataDir, OCTO_USER_DIR)
            Log.i(TAG, "ServerProfileStore: restoring $OCTO_USER_DIR for $profileId")
            move(userDir, destination)
        }
        deleteRecursively(account)
    }

    /** Renames when possible (same filesystem), copies and deletes otherwise. */
    private fun move(source: File, destination: File) {
        if (destination.exists()) deleteRecursively(destination)
        if (source.renameTo(destination)) return
        if (source.isDirectory) {
            source.copyRecursively(destination, overwrite = true)
        }
        else {
            destination.parentFile?.mkdirs()
            source.copyTo(destination, overwrite = true)
        }
        if (!source.deleteRecursively()) {
            Log.w(TAG, "ServerProfileStore: cannot delete ${source.absolutePath} after copying")
        }
    }

    private fun deleteRecursively(file: File) {
        if (!file.exists()) return
        if (!file.deleteRecursively()) {
            Log.w(TAG, "ServerProfileStore: cannot delete ${file.absolutePath}")
        }
    }

    // ---- switching -----------------------------------------------------------------------

    /**
     * Arms the relaunch and kills the process; the next start consumes `pending.json` before
     * anything else runs. A restart is unavoidable because UnityTLS caches its trust anchors.
     */
    fun requestSwitch(activity: Activity, targetId: String) {
        val filesDir = activity.filesDir
        writePendingTarget(filesDir, targetId)
        val relaunch = try {
            activity.packageManager.getLaunchIntentForPackage(activity.packageName)
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerProfileStore: cannot build the launch intent", t)
            null
        }
        if (relaunch == null) {
            Log.e(TAG, "ServerProfileStore: no launch intent for ${activity.packageName}; aborting switch")
            deletePending(filesDir)
            return
        }
        try {
            val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT
            val pendingIntent = PendingIntent.getActivity(activity, 0, relaunch, flags)
            val alarmManager = activity.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
            if (alarmManager != null) {
                alarmManager.set(
                    AlarmManager.RTC,
                    System.currentTimeMillis() + 500L,
                    pendingIntent
                )
            }
            else {
                activity.startActivity(relaunch)
            }
        }
        catch (t: Throwable) {
            Log.e(TAG, "ServerProfileStore: cannot schedule the relaunch", t)
            deletePending(filesDir)
            return
        }
        try {
            activity.finishAffinity()
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerProfileStore: finishAffinity failed", t)
        }
        Process.killProcess(Process.myPid())
    }

    // ---- URL helpers ---------------------------------------------------------------------

    data class ServerAddress(
        val scheme: String,
        val host: String,
        val port: Int,
        val explicitPort: Boolean,
        /** Canonical URL: lowercase scheme and host, no trailing slash, default port omitted. */
        val url: String,
        val label: String,
    )

    /**
     * Parses `host:port`, `https://host[:port]`, `http://host[:port]`, with an optional
     * `#sha256=<64 hex>` fragment that is returned separately by [parseServerInput].
     */
    fun parseServerAddress(raw: String): ServerAddress? {
        var value = raw.trim()
        if (value.isEmpty()) return null
        val fragment = value.indexOf('#')
        if (fragment >= 0) value = value.substring(0, fragment).trim()
        if (value.isEmpty()) return null

        val scheme: String
        var authority: String
        val schemeEnd = value.indexOf("://")
        if (schemeEnd >= 0) {
            scheme = value.substring(0, schemeEnd).lowercase(Locale.ROOT)
            authority = value.substring(schemeEnd + 3)
        }
        else {
            scheme = "https"
            authority = value
        }
        if (scheme != "https" && scheme != "http") return null

        val slash = authority.indexOf('/')
        if (slash >= 0) {
            // Tolerate a trailing slash only; a path is not a server address.
            if (slash != authority.length - 1) return null
            authority = authority.substring(0, slash)
        }
        val at = authority.lastIndexOf('@')
        if (at >= 0) authority = authority.substring(at + 1)
        if (authority.isEmpty()) return null

        val defaultPort = if (scheme == "https") DEFAULT_HTTPS_PORT else DEFAULT_HTTP_PORT
        val bracketEnd = authority.indexOf(']')
        val colon = authority.lastIndexOf(':')
        val host: String
        val port: Int
        val explicitPort: Boolean
        if (colon < 0 || (bracketEnd in 0 until colon)) {
            host = authority
            port = defaultPort
            explicitPort = false
        }
        else {
            host = authority.substring(0, colon)
            port = authority.substring(colon + 1).toIntOrNull() ?: return null
            explicitPort = true
        }
        val normalizedHost = host.trim().removePrefix("[").removeSuffix("]").lowercase(Locale.ROOT)
        if (normalizedHost.isEmpty() || port !in 1..65535) return null
        val url = buildString {
            append(scheme).append("://").append(normalizedHost)
            if (port != defaultPort) append(':').append(port)
        }
        val label = buildString {
            append(normalizedHost)
            if (explicitPort) append(':').append(port)
        }
        return ServerAddress(scheme, normalizedHost, port, explicitPort, url, label)
    }

    data class ServerInput(val address: ServerAddress, val sha256Pin: String?)

    /** Parses a user-entered server address, including the optional `#sha256=` pin. */
    fun parseServerInput(raw: String): ServerInput? {
        val address = parseServerAddress(raw) ?: return null
        val fragmentIndex = raw.indexOf('#')
        var pin: String? = null
        if (fragmentIndex >= 0) {
            val fragment = raw.substring(fragmentIndex + 1).trim()
            val prefix = "sha256="
            if (!fragment.startsWith(prefix, ignoreCase = true)) return null
            val hex = fragment.substring(prefix.length).replace(":", "").replace(" ", "").trim()
            if (hex.length != 64 || !hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return null
            pin = hex.uppercase(Locale.ROOT)
        }
        return ServerInput(address, pin)
    }

    /** Stable id: `private-` plus the first 8 hex chars of the SHA-1 of the canonical URL. */
    fun profileIdFor(normalizedUrl: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
            .digest(normalizedUrl.toByteArray(Charsets.UTF_8))
        val hex = digest.joinToString("") { "%02x".format(it) }
        return "private-" + hex.substring(0, 8)
    }

    fun buildPrivateProfile(rawUrl: String, caPem: String): ServerProfile? {
        val address = parseServerAddress(rawUrl) ?: return null
        val cert = parseFirstCertificate(caPem) ?: return null
        return ServerProfile(
            id = profileIdFor(address.url),
            kind = ServerProfile.KIND_PRIVATE,
            url = address.url,
            caPem = caPem.trim(),
            caSha256 = sha256Fingerprint(cert),
            label = address.label
        )
    }

    // ---- certificates --------------------------------------------------------------------

    fun parseFirstCertificate(pem: String): X509Certificate? {
        return try {
            val factory = CertificateFactory.getInstance("X.509")
            val match = Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")
                .find(pem)
                ?: return null
            factory.generateCertificate(
                java.io.ByteArrayInputStream(match.value.toByteArray(Charsets.US_ASCII))
            ) as? X509Certificate
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerProfileStore: cannot parse the CA PEM", t)
            null
        }
    }

    /** Uppercase colon-separated SHA-256 over the certificate's DER encoding. */
    fun sha256Fingerprint(certificate: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
        return digest.joinToString(":") { "%02X".format(it) }
    }

    /** Compares fingerprints ignoring case, colons and whitespace. */
    fun fingerprintMatches(expected: String, actual: String): Boolean {
        fun normalize(value: String) = value.replace(":", "").replace(" ", "").trim().uppercase(Locale.ROOT)
        return normalize(expected) == normalize(actual)
    }

    // ---- legacy CA cache -----------------------------------------------------------------

    private data class LegacyCachedCa(val pem: String, val url: String, val enabled: Boolean)

    private fun readLegacyCachedCa(file: File): LegacyCachedCa? {
        if (!file.isFile) return null
        val text = try {
            file.readText()
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerProfileStore: cannot read the legacy CA cache", t)
            return null
        }
        var enabled = false
        var url = ""
        var marked = false
        val pemLines = ArrayList<String>()
        for (line in text.lineSequence()) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith(LEGACY_ENABLED_PREFIX) -> {
                    enabled = trimmed.removePrefix(LEGACY_ENABLED_PREFIX).trim()
                        .equals("true", ignoreCase = true)
                    marked = true
                }
                trimmed.startsWith(LEGACY_SAVED_AT_PREFIX) -> marked = true
                trimmed.startsWith(LEGACY_URL_PREFIX) ->
                    url = trimmed.removePrefix(LEGACY_URL_PREFIX).trim()
                trimmed.startsWith("#") -> Unit
                else -> pemLines.add(line)
            }
        }
        val pem = pemLines.joinToString("\n").trim()
        if (!marked || pem.isEmpty()) return null
        return LegacyCachedCa(pem, url, enabled)
    }
}
