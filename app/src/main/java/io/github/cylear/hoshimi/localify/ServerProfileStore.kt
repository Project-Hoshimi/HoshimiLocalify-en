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
import java.io.FileOutputStream
import java.io.IOException
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

/**
 * Journal of an in-flight account swap, consumed at process start.
 *
 * [phase] is one of `begin`, `stashing`, `stashed` and `restoring`. [attempts] is
 * incremented and persisted before any file work so an interrupted run can be detected.
 */
@Serializable
private data class PendingProfileFile(
    val targetId: String,
    val fromId: String = "",
    val phase: String = "begin",
    val attempts: Int = 0,
)

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
    private const val ACCOUNT_NEW_DIR_NAME = "account.new"
    private const val ACCOUNT_OLD_DIR_NAME = "account.old"

    private const val PHASE_BEGIN = "begin"
    private const val PHASE_STASHING = "stashing"
    private const val PHASE_STASHED = "stashed"
    private const val PHASE_RESTORING = "restoring"
    private const val MAX_SWAP_ATTEMPTS = 3

    private const val CORRUPT_SUFFIX = ".corrupt"
    private const val TEMP_SUFFIX = ".tmp"

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

    // ---- atomic file writes --------------------------------------------------------------

    /**
     * Writes [text] to `<name>.tmp`, fsyncs it and renames it over [target]. A failure is logged at
     * Error and rethrown so callers that must not continue (the account swap) can react.
     */
    private fun writeAtomically(target: File, text: String) {
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, target.name + TEMP_SUFFIX)
        try {
            FileOutputStream(temp).use { out ->
                out.write(text.toByteArray(Charsets.UTF_8))
                out.flush()
                out.fd.sync()
            }
            if (!temp.renameTo(target)) {
                // renameTo does not replace on every filesystem; fall back to delete + rename.
                if (target.exists() && !target.delete()) {
                    throw IOException("cannot replace ${target.absolutePath}")
                }
                if (!temp.renameTo(target)) {
                    throw IOException("cannot rename ${temp.absolutePath} to ${target.absolutePath}")
                }
            }
        }
        catch (t: Throwable) {
            Log.e(TAG, "ServerProfileStore: cannot write ${target.absolutePath}", t)
            try {
                temp.delete()
            }
            catch (ignored: Throwable) {
            }
            throw t
        }
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
        var corrupt = false
        val parsed = try {
            if (file.isFile) {
                json.decodeFromString(profileListSerializer, file.readText())
            }
            else {
                emptyList()
            }
        }
        catch (t: Throwable) {
            corrupt = true
            Log.e(TAG, "ServerProfileStore: cannot parse ${file.absolutePath}", t)
            // Keep the bad file for diagnosis, but never rebuild it over the top.
            try {
                val corruptFile = File(dir, FILE_PROFILES + CORRUPT_SUFFIX)
                if (corruptFile.exists()) corruptFile.delete()
                if (!file.renameTo(corruptFile)) {
                    file.copyTo(corruptFile, overwrite = true)
                    file.delete()
                }
                Log.e(TAG, "ServerProfileStore: kept the unreadable file as ${corruptFile.absolutePath}")
            }
            catch (moveError: Throwable) {
                Log.e(TAG, "ServerProfileStore: cannot preserve the unreadable profiles.json", moveError)
            }
            emptyList()
        }
        val result = ArrayList<ServerProfile>(parsed.size + 1)
        result.add(parsed.firstOrNull { it.id == ServerProfile.OFFICIAL_ID } ?: officialProfile())
        for (profile in parsed) {
            if (profile.id == ServerProfile.OFFICIAL_ID) continue
            if (result.any { it.id == profile.id }) continue
            result.add(profile)
        }
        // A corrupt file is treated as empty for this run only; do not overwrite it here.
        if (!corrupt &&
            (result.size != parsed.size || result.firstOrNull()?.kind != ServerProfile.KIND_OFFICIAL)
        ) {
            saveProfilesLocked(filesDir, result)
        }
        return result
    }

    private fun saveProfilesLocked(filesDir: File, profiles: List<ServerProfile>) {
        try {
            writeAtomically(
                File(profilesDir(filesDir), FILE_PROFILES),
                json.encodeToString(profileListSerializer, profiles)
            )
        }
        catch (t: Throwable) {
            Log.e(TAG, "ServerProfileStore: cannot write profiles.json", t)
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

    /** True when `active.json` exists, even if it cannot be read. */
    fun hasActiveId(filesDir: File): Boolean {
        synchronized(lock) {
            return File(profilesDir(filesDir), FILE_ACTIVE).isFile
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
            try {
                writeActiveIdLocked(filesDir, profileId)
            }
            catch (t: Throwable) {
                Log.e(TAG, "ServerProfileStore: cannot write active.json", t)
            }
        }
    }

    private fun writeActiveIdLocked(filesDir: File, profileId: String) {
        writeAtomically(
            File(profilesDir(filesDir), FILE_ACTIVE),
            json.encodeToString(ActiveProfileFile.serializer(), ActiveProfileFile(profileId))
        )
        Log.i(TAG, "ServerProfileStore: active profile -> $profileId")
    }

    fun readPendingTarget(filesDir: File): String? {
        synchronized(lock) {
            return readPendingLocked(filesDir)?.targetId
        }
    }

    private fun readPendingLocked(filesDir: File): PendingProfileFile? {
        val file = File(profilesDir(filesDir), FILE_PENDING)
        return try {
            if (!file.isFile) return null
            val pending = json.decodeFromString(PendingProfileFile.serializer(), file.readText())
            if (pending.targetId.isBlank()) return null
            val phase = when (pending.phase) {
                PHASE_BEGIN -> PHASE_BEGIN
                PHASE_STASHING -> PHASE_STASHING
                PHASE_STASHED -> PHASE_STASHED
                PHASE_RESTORING -> PHASE_RESTORING
                else -> PHASE_BEGIN
            }
            pending.copy(phase = phase)
        }
        catch (t: Throwable) {
            Log.e(TAG, "ServerProfileStore: cannot read pending.json", t)
            null
        }
    }

    /** Starts a switch journal. Returns false when the journal could not be persisted. */
    private fun beginPendingSwitchLocked(filesDir: File, targetId: String): Boolean {
        val fromId = readActiveIdLocked(filesDir) ?: ServerProfile.OFFICIAL_ID
        return try {
            writePendingLocked(
                filesDir,
                PendingProfileFile(
                    targetId = targetId,
                    fromId = fromId,
                    phase = PHASE_BEGIN,
                    attempts = 0
                )
            )
            Log.i(TAG, "ServerProfileStore: pending switch -> $targetId (from $fromId)")
            true
        }
        catch (t: Throwable) {
            Log.e(TAG, "ServerProfileStore: cannot write pending.json", t)
            false
        }
    }

    private fun writePendingLocked(filesDir: File, pending: PendingProfileFile) {
        writeAtomically(
            File(profilesDir(filesDir), FILE_PENDING),
            json.encodeToString(PendingProfileFile.serializer(), pending)
        )
    }

    fun writePendingTarget(filesDir: File, targetId: String): Boolean {
        synchronized(lock) {
            return beginPendingSwitchLocked(filesDir, targetId)
        }
    }

    fun deletePending(filesDir: File) {
        synchronized(lock) {
            deletePendingLocked(filesDir)
        }
    }

    private fun deletePendingLocked(filesDir: File) {
        val file = File(profilesDir(filesDir), FILE_PENDING)
        try {
            if (file.isFile) {
                file.delete()
                Log.i(TAG, "ServerProfileStore: pending switch cleared")
            }
        }
        catch (t: Throwable) {
            Log.e(TAG, "ServerProfileStore: cannot delete pending.json", t)
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
            val profiles = loadProfilesLocked(filesDir)
            val profile = profiles.firstOrNull {
                it.id == activeId && it.kind == ServerProfile.KIND_PRIVATE && it.url.isNotBlank()
            }
            if (profile == null) {
                Log.e(
                    TAG,
                    "ServerProfileStore: active.json names missing or unusable profile $activeId; " +
                            "treating the official server as active (active.json left untouched)"
                )
            }
            return profile
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
            try {
                writeActiveIdLocked(filesDir, ServerProfile.OFFICIAL_ID)
            }
            catch (t: Throwable) {
                Log.e(TAG, "ServerProfileStore: cannot persist the initial active profile", t)
            }
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
     * Consumes `pending.json` through a small journaled protocol:
     *
     *  1. `begin`     - drop any stale `account.new`, then move to `stashing`.
     *  2. `stashing`  - move every live account file into `<from>/account.new` (idempotent).
     *  3. `stashed`   - replace `<from>/account` with `account.new` (recoverable).
     *  4. `restoring` - copy (never move) `<target>/account` back to the live locations, then
     *                   atomically flip `active.json` and delete `pending.json`.
     *
     * The attempt counter is persisted before any file work. Up to [MAX_SWAP_ATTEMPTS] launches
     * retry the persisted phase; beyond that the swap is aborted and the `from` account is restored.
     * Runs before Firebase's ContentProvider in the new process, so no component can read a token
     * that belongs to the previous server.
     */
    fun swapPendingAccount(dataDir: File) {
        val filesDir = File(dataDir, "files")
        synchronized(lock) {
            val stored = readPendingLocked(filesDir) ?: return
            val fromId = stored.fromId.takeIf { it.isNotBlank() }
                ?: readActiveIdLocked(filesDir)
                ?: ServerProfile.OFFICIAL_ID
            var state = stored.copy(fromId = fromId)

            if (state.targetId == state.fromId) {
                Log.i(
                    TAG,
                    "ServerProfileStore: pending target ${state.targetId} is already active; nothing to swap"
                )
                deletePendingLocked(filesDir)
                return
            }

            state = state.copy(attempts = state.attempts + 1)
            try {
                writePendingLocked(filesDir, state)
            }
            catch (t: Throwable) {
                // Without a persisted attempt counter a retry could loop forever; stop here.
                Log.e(
                    TAG,
                    "ServerProfileStore: cannot persist the swap journal; leaving pending.json untouched",
                    t
                )
                return
            }

            if (state.attempts > MAX_SWAP_ATTEMPTS) {
                abortSwap(dataDir, filesDir, state)
                return
            }

            Log.i(
                TAG,
                "ServerProfileStore: account swap ${state.fromId} -> ${state.targetId} " +
                        "(attempt ${state.attempts}, phase ${state.phase})"
            )

            try {
                while (true) {
                    when (state.phase) {
                        PHASE_BEGIN -> {
                            // A leftover account.new belongs to an interrupted earlier attempt.
                            deleteRecursively(
                                File(File(profilesDir(filesDir), state.fromId), ACCOUNT_NEW_DIR_NAME)
                            )
                            state = state.copy(phase = PHASE_STASHING)
                            writePendingLocked(filesDir, state)
                        }

                        PHASE_STASHING -> {
                            stashAccountFiles(dataDir, filesDir, state.fromId)
                            state = state.copy(phase = PHASE_STASHED)
                            writePendingLocked(filesDir, state)
                        }

                        PHASE_STASHED -> {
                            replaceStash(filesDir, state.fromId)
                            state = state.copy(phase = PHASE_RESTORING)
                            writePendingLocked(filesDir, state)
                        }

                        PHASE_RESTORING -> {
                            restoreAccountFiles(dataDir, filesDir, state.targetId)
                            writeActiveIdLocked(filesDir, state.targetId)
                            deletePendingLocked(filesDir)
                            Log.i(
                                TAG,
                                "ServerProfileStore: server switch to ${state.targetId} complete; " +
                                        "the per-profile stash is kept as a backup"
                            )
                            return
                        }

                        else -> {
                            state = state.copy(phase = PHASE_BEGIN)
                            writePendingLocked(filesDir, state)
                        }
                    }
                }
            }
            catch (t: Throwable) {
                if (state.attempts > MAX_SWAP_ATTEMPTS) {
                    abortSwap(dataDir, filesDir, state)
                }
                else {
                    // Keep the journal: the next launch retries from the persisted phase.
                    Log.e(
                        TAG,
                        "ServerProfileStore: account swap ${state.fromId} -> ${state.targetId} " +
                                "failed in phase ${state.phase}; will retry on the next launch",
                        t
                    )
                }
            }
        }
    }

    /**
     * Gives up on a swap that failed too often and restores the `from` account. If the live files
     * were already moved into `account.new`, those are copied back; if the replacement happened,
     * `account` holds the `from` account. Files are copied, never moved, so the stash stays intact.
     */
    private fun abortSwap(dataDir: File, filesDir: File, state: PendingProfileFile) {
        Log.e(
            TAG,
            "ServerProfileStore: aborting account swap ${state.fromId} -> ${state.targetId} after " +
                    "${state.attempts} attempts; restoring the ${state.fromId} account"
        )
        try {
            val fromRoot = File(profilesDir(filesDir), state.fromId)
            val accountNew = File(fromRoot, ACCOUNT_NEW_DIR_NAME)
            val account = File(fromRoot, ACCOUNT_DIR_NAME)
            // account.new only holds this swap's files once stashing has started; in `begin` it may
            // be a stale leftover. After the replacement, `account` holds the from account.
            val restoreFrom = when {
                (state.phase == PHASE_STASHING || state.phase == PHASE_STASHED) &&
                        accountNew.isDirectory -> accountNew
                (state.phase == PHASE_STASHED || state.phase == PHASE_RESTORING) &&
                        account.isDirectory -> account
                else -> null
            }
            if (restoreFrom != null) {
                // While stashing, some live files were not moved yet: keep them and only put the
                // stashed ones back. Once fully stashed, anything live belongs to the target.
                if (state.phase == PHASE_STASHED || state.phase == PHASE_RESTORING) {
                    for (entry in accountEntries(dataDir)) deleteRecursively(entry)
                }
                copyStashToLive(dataDir, restoreFrom)
                Log.e(TAG, "ServerProfileStore: live account files restored from ${restoreFrom.absolutePath}")
            }
            else {
                Log.e(TAG, "ServerProfileStore: live account files were never stashed; leaving them in place")
            }
            try {
                writeActiveIdLocked(filesDir, state.fromId)
            }
            catch (t: Throwable) {
                Log.e(TAG, "ServerProfileStore: cannot restore active.json to ${state.fromId}", t)
            }
        }
        finally {
            deletePendingLocked(filesDir)
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

    /**
     * Moves every live account file into `<profileId>/account.new`. Safe to call again after a
     * crash: entries that were already moved are simply no longer live.
     */
    private fun stashAccountFiles(dataDir: File, filesDir: File, profileId: String) {
        val stashing = File(File(profilesDir(filesDir), profileId), ACCOUNT_NEW_DIR_NAME)
        stashing.mkdirs()
        for (entry in accountEntries(dataDir)) {
            val relative = entry.relativeTo(dataDir).path
            val destination = File(stashing, relative)
            destination.parentFile?.mkdirs()
            Log.i(TAG, "ServerProfileStore: stashing $relative for $profileId")
            move(entry, destination)
        }
    }

    /**
     * Replaces `<profileId>/account` with `account.new`. Recoverable: `account.new` may already be
     * missing when the rename completed before a crash, and `account` may be missing after the
     * first rename. Leaves no `account.old` behind.
     */
    private fun replaceStash(filesDir: File, profileId: String) {
        val root = File(profilesDir(filesDir), profileId)
        val account = File(root, ACCOUNT_DIR_NAME)
        val stashing = File(root, ACCOUNT_NEW_DIR_NAME)
        val old = File(root, ACCOUNT_OLD_DIR_NAME)

        if (!stashing.exists() && account.exists()) {
            // The replacement already happened in an earlier attempt.
            deleteRecursively(old)
            return
        }
        if (old.exists() && !account.exists()) {
            // Crashed after `account` was renamed to `account.old`.
            if (stashing.exists() && !stashing.renameTo(account)) {
                throw IOException("cannot rename ${stashing.absolutePath} to ${account.absolutePath}")
            }
            deleteRecursively(old)
            return
        }
        if (account.exists()) {
            deleteRecursively(old)
            if (!account.renameTo(old)) {
                throw IOException("cannot rename ${account.absolutePath} to ${old.absolutePath}")
            }
        }
        if (stashing.exists() && !stashing.renameTo(account)) {
            throw IOException("cannot rename ${stashing.absolutePath} to ${account.absolutePath}")
        }
        deleteRecursively(old)
    }

    /**
     * Copies the target profile's stash back to the live locations, deleting whatever is live at
     * each path first. The stash is never consumed, so it doubles as the profile's backup.
     */
    private fun restoreAccountFiles(dataDir: File, filesDir: File, profileId: String) {
        val account = accountDir(filesDir, profileId)
        if (!account.isDirectory) {
            Log.i(TAG, "ServerProfileStore: no saved account for $profileId; the game will create one")
            for (entry in accountEntries(dataDir)) deleteRecursively(entry)
            return
        }
        copyStashToLive(dataDir, account)
    }

    private fun copyStashToLive(dataDir: File, stash: File) {
        stash.listFiles()?.sortedBy { it.name }?.forEach { source ->
            copyEntryToLive(dataDir, stash, source)
        }
    }

    private fun copyEntryToLive(dataDir: File, stashRoot: File, source: File) {
        val relative = source.relativeTo(stashRoot).path
        val destination = File(dataDir, relative)
        if (source.isDirectory) {
            destination.mkdirs()
            source.listFiles()?.sortedBy { it.name }?.forEach { child ->
                copyEntryToLive(dataDir, stashRoot, child)
            }
            return
        }
        destination.parentFile?.mkdirs()
        if (destination.exists()) deleteRecursively(destination)
        Log.i(TAG, "ServerProfileStore: restoring $relative")
        source.copyTo(destination, overwrite = true)
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
        if (!writePendingTarget(filesDir, targetId)) {
            Log.e(TAG, "ServerProfileStore: cannot journal the switch to $targetId; not relaunching")
            return
        }
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
