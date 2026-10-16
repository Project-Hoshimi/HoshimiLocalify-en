package io.github.cylear.hoshimi.localify

import android.content.Context
import android.content.pm.PackageManager

object TargetGamePackages {
    const val IDOLY_PRIDE = "game.qualiarts.idolypride"
    const val IDOLY_PRIDE_KR = "game.qualiarts.idolypride_kr"
    const val IDOLY_PRIDE_EN = "game.qualiarts.idolypride_en"

    val all = listOf(
        IDOLY_PRIDE,
        IDOLY_PRIDE_KR,
        IDOLY_PRIDE_EN,
    )

    fun findInstalled(context: Context): String? {
        return all.firstOrNull {
            try {
                context.packageManager.getPackageInfo(it, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }
    }
}
