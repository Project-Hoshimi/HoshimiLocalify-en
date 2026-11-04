package io.github.cylear.hoshimi.localify

import android.app.Activity
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.FrameLayout
import android.widget.Toast
import java.lang.ref.WeakReference

/**
 * Small native overlay on top of the Unity surface that opens the server picker.
 *
 * Unity draws its whole UI inside the activity's content FrameLayout, so a plain [Button] added
 * there stays above the game. Visibility follows the top segment of the current Unity screen
 * hierarchy, which the native text probe reports through
 * [HoshimiHookMain.onScreenRootChanged] (see `Hook.cpp` / `libHoshimiLocalify.cpp`).
 */
object ServerSwitchOverlay {
    /** Substring of the current screen root that means "title screen". Tuned after emulator tests. */
    const val TITLE_SCREEN_ROOT_MARKER = "Title"

    /**
     * Root suffixes of full game screens (e.g. `HomeWindow(Clone)`, `StoryPlayerScreen(Clone)`).
     * Only these hide the button again. Shared layers such as `Canvas` and
     * `Singleton(DontDestroy)` also report text while the title is up, so they must not count
     * as leaving the title screen.
     */
    private val GAME_SCREEN_ROOT_SUFFIXES = listOf("Window(Clone)", "Screen(Clone)")

    /** Raise the button off the bottom edge by this fraction of the screen height. */
    private const val BOTTOM_OFFSET_FRACTION = 0.15f

    private const val BUTTON_TEXT = "Switch server"
    private const val MANAGED_MESSAGE = "Server is managed by the HoshimiLocalify app"
    private const val MARGIN_DP = 12
    private const val PADDING_H_DP = 12
    private const val PADDING_V_DP = 4
    private const val BACKGROUND_COLOR = 0x66000000
    private const val TEXT_COLOR = 0xFFFFFFFF.toInt()

    private val handler = Handler(Looper.getMainLooper())

    /** Last Unity screen root reported by native code; empty until the first probe. */
    @Volatile
    private var currentRoot: String = ""

    /** Latched title state: set by a title root, cleared only by a full game screen root. */
    @Volatile
    private var onTitleScreen: Boolean = false

    /** True while the native `TitlePresenter` hooks say the title screen is up. */
    @Volatile
    private var titlePresenterActive: Boolean = false

    private var activityRef: WeakReference<Activity>? = null
    private var buttonRef: WeakReference<Button>? = null

    /** Adds the overlay to [activity]'s content view (idempotent, runs on the main thread). */
    fun attach(activity: Activity) {
        handler.post { attachOnMain(activity) }
    }

    private fun attachOnMain(activity: Activity) {
        try {
            if (activity.isFinishing) return
            val existing = buttonRef?.get()
            if (existing != null && activityRef?.get() === activity && existing.parent != null) {
                existing.visibility = currentVisibility()
                return
            }
            if (existing?.parent != null) {
                (existing.parent as? ViewGroup)?.removeView(existing)
            }
            val root = activity.findViewById<ViewGroup>(android.R.id.content) as? FrameLayout ?: return
            val button = Button(activity).apply {
                text = BUTTON_TEXT
                textSize = 12f
                isAllCaps = false
                setTextColor(TEXT_COLOR)
                setBackgroundColor(BACKGROUND_COLOR)
                alpha = 0.9f
                setPadding(
                    dp(activity, PADDING_H_DP),
                    dp(activity, PADDING_V_DP),
                    dp(activity, PADDING_H_DP),
                    dp(activity, PADDING_V_DP)
                )
                visibility = currentVisibility()
                setOnClickListener { onButtonClicked(activity) }
            }
            val params = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL
            ).apply {
                val margin = dp(activity, MARGIN_DP)
                val bottom = margin +
                        (activity.resources.displayMetrics.heightPixels * BOTTOM_OFFSET_FRACTION).toInt()
                setMargins(margin, margin, margin, bottom)
            }
            root.addView(button, params)
            activityRef = WeakReference(activity)
            buttonRef = WeakReference(button)
            Log.i(TAG, "ServerSwitch: overlay attached to ${activity.javaClass.name}")
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerSwitch: cannot attach the overlay", t)
        }
    }

    private fun onButtonClicked(activity: Activity) {
        try {
            if (ServerProfileStore.appManagedPrivateServer) {
                Toast.makeText(activity, MANAGED_MESSAGE, Toast.LENGTH_SHORT).show()
                return
            }
            ServerPromptDialog.show(activity)
        }
        catch (t: Throwable) {
            Log.w(TAG, "ServerSwitch: cannot open the server dialog", t)
        }
    }

    /**
     * Called from [HoshimiHookMain.onScreenRootChanged] on the JNI thread; hops to the main thread
     * before touching views.
     */
    fun onScreenRootChanged(root: String) {
        handler.post {
            try {
                val cleaned = cleanScreenRoot(root)
                currentRoot = cleaned
                if (cleaned.contains(TITLE_SCREEN_ROOT_MARKER, ignoreCase = true)) {
                    onTitleScreen = true
                }
                else if (GAME_SCREEN_ROOT_SUFFIXES.any { cleaned.endsWith(it) }) {
                    onTitleScreen = false
                }
                val activity = activityRef?.get() ?: return@post
                val button = buttonRef?.get() ?: return@post
                if (activity.isFinishing || activity.isDestroyed) return@post
                button.visibility = currentVisibility()
            }
            catch (t: Throwable) {
                Log.w(TAG, "ServerSwitch: cannot update the overlay visibility", t)
            }
        }
    }

    /**
     * Called from [HoshimiHookMain.onTitleScreenChanged] on the JNI thread; the title presenter
     * is the authoritative source, the screen-root probe stays as a fallback.
     */
    fun onTitleScreenChanged(visible: Boolean) {
        handler.post {
            try {
                titlePresenterActive = visible
                onTitleScreen = visible
                Log.i(TAG, "ServerSwitch: title presenter -> visible=$visible")
                val activity = activityRef?.get() ?: return@post
                val button = buttonRef?.get() ?: return@post
                if (activity.isFinishing || activity.isDestroyed) return@post
                button.visibility = currentVisibility()
            }
            catch (t: Throwable) {
                Log.w(TAG, "ServerSwitch: cannot update the overlay from the title presenter", t)
            }
        }
    }

    private fun currentVisibility(): Int =
        if (titlePresenterActive || onTitleScreen) View.VISIBLE else View.GONE

    /** Drops the ` [component=...]` suffix and anything after the first path separator. */
    private fun cleanScreenRoot(root: String): String {
        var value = root
        val suffix = value.indexOf(" [component=")
        if (suffix >= 0) value = value.substring(0, suffix)
        val slash = value.indexOf('/')
        if (slash >= 0) value = value.substring(0, slash)
        return value
    }

    private fun dp(activity: Activity, value: Int): Int =
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            value.toFloat(),
            activity.resources.displayMetrics
        ).toInt()
}
