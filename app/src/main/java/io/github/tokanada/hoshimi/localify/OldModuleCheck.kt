package io.github.tokanada.hoshimi.localify

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.foundation.layout.Row
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource

/**
 * Detects the previous HoshimiLocalify module package so the companion app can suggest removing it.
 *
 * v1.5.0 uses a new application id, so both modules can be installed at the same time; leaving the
 * old one enabled in LSPosed would hook the game twice.
 */
object OldModuleCheck {
    const val OLD_PACKAGE = "io.github.cylear.hoshimi.localify"
    const val PREFS_NAME = "migration_prefs"
    const val KEY_HIDE_OLD_MODULE_PROMPT = "hide_old_module_prompt"

    /** True when [OLD_PACKAGE] is installed and visible to this app (see the manifest `<queries>`). */
    fun isInstalled(context: Context): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(
                    OLD_PACKAGE,
                    PackageManager.PackageInfoFlags.of(0)
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(OLD_PACKAGE, 0)
            }
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    fun isPromptHidden(context: Context): Boolean {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_HIDE_OLD_MODULE_PROMPT, false)
    }

    fun setPromptHidden(context: Context, hidden: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_HIDE_OLD_MODULE_PROMPT, hidden)
            .apply()
    }

    fun uninstallIntent(): Intent {
        return Intent(Intent.ACTION_DELETE, Uri.parse("package:$OLD_PACKAGE"))
    }
}

/** Compose dialog shown on app start while [OldModuleCheck.OLD_PACKAGE] is still installed. */
@Composable
fun OldModulePromptDialog(
    onUninstall: () -> Unit,
    onLater: () -> Unit,
    onDontShowAgain: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onLater,
        title = { Text(stringResource(R.string.old_module_prompt_title)) },
        text = { Text(stringResource(R.string.old_module_prompt_message)) },
        confirmButton = {
            TextButton(onClick = onUninstall) {
                Text(stringResource(R.string.old_module_uninstall))
            }
        },
        dismissButton = {
            Row {
                TextButton(onClick = onLater) {
                    Text(stringResource(R.string.old_module_later))
                }
                TextButton(onClick = onDontShowAgain) {
                    Text(stringResource(R.string.old_module_dont_show_again))
                }
            }
        }
    )
}
