package io.github.cylear.hoshimi.localify

import android.app.Activity
import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.SystemClock
import android.util.Log
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection

/**
 * Local notifications for idol messages and phone calls.
 *
 * The official game receives these as FCM pushes, which a private server cannot deliver. Instead,
 * this object polls the private server's pending list whenever the game goes to the background and
 * turns every future item into an exact alarm. The alarm fires a broadcast at the game's own
 * UnityNotificationRestartReceiver (declared in the game manifest, hooked below), which then posts
 * a normal Android notification.
 *
 * Runs inside the game process, so it uses framework APIs only (no androidx).
 */
object NarrativeNotifier {
    private const val TAG = "NarrativeNotifier"
    private const val ACTION_NOTIFY = "io.github.cylear.hoshimi.localify.NARRATIVE_NOTIFY"
    private const val CHANNEL_ID = "hoshimi_narrative"
    private const val CHANNEL_NAME = "アイドルからの連絡"
    private const val PREFS_NAME = "hoshimi_narrative_notify"
    private const val KEY_SCHEDULED = "scheduled"
    private const val RECEIVER_CLASS = "com.unity.androidnotifications.UnityNotificationRestartReceiver"
    private const val URI_SCHEME = "hoshimi-narrative"
    private const val KIND_MESSAGE = "message"
    private const val KIND_TELEPHONE = "telephone"
    private const val EXTRA_KIND = "kind"
    private const val EXTRA_ID = "id"
    private const val EXTRA_CHARACTER_NAME = "characterName"
    private const val EXTRA_TITLE = "title"
    private const val FALLBACK_CHARACTER_NAME = "アイドル"
    private const val BACKGROUND_DEBOUNCE_MS = 5_000L
    private const val TIMEOUT_MS = 10_000

    private val installed = AtomicBoolean(false)
    private val lastBackgroundAt = AtomicLong(0L)

    /** Hooks the pause trigger and the alarm receiver. Must run early in the game process. */
    fun install(classLoader: ClassLoader) {
        if (!installed.compareAndSet(false, true)) {
            return
        }
        try {
            val activityClass = XposedHelpers.findClass("android.app.Activity", classLoader)
            XposedBridge.hookAllMethods(activityClass, "onPause", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val activity = param.thisObject as? Activity ?: return
                    onBackground(activity)
                }
            })
            Log.i(TAG, "hooked Activity.onPause")
        }
        catch (t: Throwable) {
            Log.w(TAG, "cannot hook Activity.onPause", t)
        }

        try {
            XposedHelpers.findAndHookMethod(
                RECEIVER_CLASS,
                classLoader,
                "onReceive",
                Context::class.java,
                Intent::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val context = param.args.getOrNull(0) as? Context ?: return
                        val intent = param.args.getOrNull(1) as? Intent ?: return
                        if (intent.action != ACTION_NOTIFY) {
                            return
                        }
                        postNotification(context, intent)
                        // Our alarm is not a Unity notification; skip the original receiver.
                        param.result = null
                    }
                }
            )
            Log.i(TAG, "hooked $RECEIVER_CLASS.onReceive")
        }
        catch (t: Throwable) {
            Log.w(TAG, "cannot hook $RECEIVER_CLASS.onReceive", t)
        }
    }

    /** Debounced: the game can pause/resume several times in a row. */
    private fun onBackground(activity: Activity) {
        val now = SystemClock.elapsedRealtime()
        val last = lastBackgroundAt.get()
        if (now - last < BACKGROUND_DEBOUNCE_MS || !lastBackgroundAt.compareAndSet(last, now)) {
            return
        }
        val ctx = activity.applicationContext ?: return
        Thread {
            try {
                refresh(ctx)
            }
            catch (t: Throwable) {
                Log.w(TAG, "background refresh failed", t)
            }
        }.start()
    }

    private fun refresh(ctx: Context) {
        val token = try {
            HoshimiHookMain.getGameAuthToken()
        }
        catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "native library unavailable; cannot read the game auth token", e)
            return
        }
        val baseUrl = PrivateServerTrust.currentServerUrl()
        if (token.isEmpty() || baseUrl.isEmpty()) {
            Log.d(TAG, "no auth token or private server URL; skipping the pending check")
            return
        }

        val items = fetchPending(token, baseUrl)
        if (items == null) {
            // Never cancel the existing alarms on a transient failure.
            Log.w(TAG, "pending list unavailable; keeping the scheduled notifications")
            return
        }

        cancelAll(ctx)
        val now = System.currentTimeMillis()
        val scheduled = ArrayList<String>()
        for (index in 0 until items.length()) {
            val item = items.optJSONObject(index) ?: continue
            val dueAt = item.optLong("dueAt", 0L)
            if (dueAt <= now) {
                continue
            }
            schedule(ctx, item, dueAt)?.let { scheduled.add(it) }
        }
        storeSchedules(ctx, scheduled)
        Log.i(TAG, "scheduled ${scheduled.size} notifications")
    }

    /** Returns the `items` array, or null when the list could not be fetched. */
    private fun fetchPending(token: String, baseUrl: String): JSONArray? {
        var connection: HttpURLConnection? = null
        return try {
            val url = URL(baseUrl.trimEnd('/') + "/mod/narrative/pending")
            val opened = url.openConnection() as HttpURLConnection
            connection = opened
            if (opened is HttpsURLConnection) {
                PrivateServerTrust.sslSocketFactory()?.let { opened.sslSocketFactory = it }
            }
            opened.requestMethod = "GET"
            opened.connectTimeout = TIMEOUT_MS
            opened.readTimeout = TIMEOUT_MS
            opened.useCaches = false
            opened.setRequestProperty("x-auth-token", token)
            opened.setRequestProperty("Accept", "application/json")
            val code = opened.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "pending request failed with HTTP $code")
                return null
            }
            val body = opened.inputStream.bufferedReader().use { it.readText() }
            JSONObject(body).optJSONArray("items") ?: JSONArray()
        }
        catch (t: Throwable) {
            Log.w(TAG, "pending request failed", t)
            null
        }
        finally {
            connection?.disconnect()
        }
    }

    /** Arms one alarm; returns the stored data URI so it can be cancelled later. */
    private fun schedule(ctx: Context, item: JSONObject, dueAt: Long): String? {
        val kind = item.optString(EXTRA_KIND)
        val id = item.optString(EXTRA_ID)
        if (kind.isEmpty() || id.isEmpty()) {
            return null
        }
        val uri = Uri.Builder()
            .scheme(URI_SCHEME)
            .authority(kind)
            .appendPath(id)
            .build()
        val intent = Intent(ACTION_NOTIFY).apply {
            setClassName(ctx.packageName, RECEIVER_CLASS)
            data = uri
            putExtra(EXTRA_KIND, kind)
            putExtra(EXTRA_ID, id)
            putExtra(EXTRA_CHARACTER_NAME, item.optString(EXTRA_CHARACTER_NAME))
            putExtra(EXTRA_TITLE, item.optString(EXTRA_TITLE))
        }
        val pendingIntent = PendingIntent.getBroadcast(
            ctx,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val alarmManager = ctx.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return null
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !alarmManager.canScheduleExactAlarms()) {
                alarmManager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, dueAt, pendingIntent)
            }
            else {
                alarmManager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, dueAt, pendingIntent)
            }
        }
        catch (t: Throwable) {
            Log.w(TAG, "cannot schedule $kind/$id", t)
            return null
        }
        Log.i(TAG, "scheduled $kind $id at $dueAt")
        return uri.toString()
    }

    private fun cancelAll(ctx: Context) {
        val alarmManager = ctx.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
        for (stored in storedSchedules(ctx)) {
            try {
                val intent = Intent(ACTION_NOTIFY).apply {
                    setClassName(ctx.packageName, RECEIVER_CLASS)
                    data = Uri.parse(stored)
                }
                val pendingIntent = PendingIntent.getBroadcast(
                    ctx,
                    0,
                    intent,
                    PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE
                ) ?: continue
                alarmManager?.cancel(pendingIntent)
                pendingIntent.cancel()
            }
            catch (t: Throwable) {
                Log.w(TAG, "cannot cancel $stored", t)
            }
        }
        storeSchedules(ctx, emptyList())
    }

    private fun postNotification(ctx: Context, intent: Intent) {
        val kind = intent.getStringExtra(EXTRA_KIND).orEmpty()
        val id = intent.getStringExtra(EXTRA_ID).orEmpty()
        val characterName = intent.getStringExtra(EXTRA_CHARACTER_NAME).orEmpty()
            .ifEmpty { FALLBACK_CHARACTER_NAME }
        val title = intent.getStringExtra(EXTRA_TITLE).orEmpty()
        val notificationId = (kind + ":" + id).hashCode()

        try {
            ensureChannel(ctx)
            val builder = Notification.Builder(ctx, CHANNEL_ID)
                .setSmallIcon(ctx.applicationInfo.icon)
                .setAutoCancel(true)
                .setContentIntent(contentPendingIntent(ctx, notificationId))
            when (kind) {
                KIND_MESSAGE -> {
                    builder.setContentTitle("${characterName}からメッセージが届きました")
                    if (title.isNotEmpty()) {
                        builder.setContentText(title)
                    }
                    builder.setCategory(Notification.CATEGORY_MESSAGE)
                }
                KIND_TELEPHONE -> {
                    builder.setContentTitle("${characterName}から着信")
                    builder.setCategory(Notification.CATEGORY_CALL)
                }
                else -> {
                    builder.setContentTitle(characterName)
                    builder.setCategory(Notification.CATEGORY_MESSAGE)
                }
            }
            val manager = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.notify(notificationId, builder.build())
            removeScheduled(ctx, intent.dataString)
        }
        catch (e: SecurityException) {
            Log.w(TAG, "cannot post the $kind notification", e)
        }
    }

    private fun ensureChannel(ctx: Context) {
        val manager = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH)
        manager.createNotificationChannel(channel)
    }

    /** Tapping the notification must enter the game through the module's normal StartGame path. */
    private fun contentPendingIntent(ctx: Context, notificationId: Int): PendingIntent {
        val intent = Intent()
            .setClassName(BuildConfig.APPLICATION_ID, "io.github.cylear.hoshimi.localify.MainActivity")
            .putExtra(MainActivity.EXTRA_AUTO_START_GAME, true)
            .putExtra(MainActivity.EXTRA_GAME_PACKAGE, ctx.packageName)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return PendingIntent.getActivity(
            ctx,
            notificationId,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    // ---- stored schedule ------------------------------------------------------------------

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun storedSchedules(ctx: Context): List<String> {
        val raw = prefs(ctx).getString(KEY_SCHEDULED, null) ?: return emptyList()
        return try {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { index ->
                array.optString(index, "").takeIf { it.isNotEmpty() }
            }
        }
        catch (t: Throwable) {
            Log.w(TAG, "cannot read the scheduled notification list", t)
            emptyList()
        }
    }

    private fun storeSchedules(ctx: Context, uris: List<String>) {
        val array = JSONArray()
        uris.forEach { array.put(it) }
        prefs(ctx).edit().putString(KEY_SCHEDULED, array.toString()).apply()
    }

    private fun removeScheduled(ctx: Context, uri: String?) {
        if (uri.isNullOrEmpty()) {
            return
        }
        storeSchedules(ctx, storedSchedules(ctx).filterNot { it == uri })
    }
}
