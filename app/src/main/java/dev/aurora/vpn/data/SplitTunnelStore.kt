package dev.aurora.vpn.data

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService

enum class SplitMode { OFF, INCLUDE, EXCLUDE }

/**
 * Persistent user-selected per-app routing. Android VpnService.Builder is the sole authority.
 * Mode INCLUDE routes ONLY listed apps, EXCLUDE routes all apps EXCEPT listed apps.
 */
class SplitTunnelStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("split_tunnel", Context.MODE_PRIVATE)

    fun mode(): SplitMode = runCatching {
        SplitMode.valueOf(prefs.getString("mode", SplitMode.OFF.name) ?: "OFF")
    }.getOrDefault(SplitMode.OFF)

    fun selectedPackages(): Set<String> = prefs.getStringSet("packages", emptySet())?.toSet().orEmpty()

    fun setMode(value: SplitMode) {
        check(prefs.edit().putString("mode", value.name).commit()) { "Could not save split tunneling" }
    }

    fun setSelectedPackages(packageNames: Set<String>) {
        require(packageNames.size <= 500) { "Too many packages" }
        require(packageNames.all { it.matches(Regex("[a-zA-Z0-9_]+(\\.[a-zA-Z0-9_]+)+")) }) {
            "Invalid app package"
        }
        check(prefs.edit().putStringSet("packages", packageNames.toSet()).commit()) {
            "Could not save app selection"
        }
    }

    fun applyTo(builder: VpnService.Builder) {
        val mode = mode()
        if (mode == SplitMode.OFF) return
        val selected = selectedPackages()
        check(selected.isNotEmpty()) { "Select an app for split tunneling" }
        var applied = 0
        selected.forEach { packageName ->
            try {
                when (mode) {
                    SplitMode.INCLUDE -> builder.addAllowedApplication(packageName)
                    SplitMode.EXCLUDE -> builder.addDisallowedApplication(packageName)
                    SplitMode.OFF -> Unit
                }
                applied++
            } catch (_: PackageManager.NameNotFoundException) {
                // App may have been uninstalled; do not apply stale package names.
            }
        }
        check(applied > 0) { "No selected apps are installed" }
    }

    /** Android 11+ package visibility is intentionally scoped to launcher apps. */
    @Suppress("DEPRECATION")
    fun launchableApps(context: Context): List<Pair<String, String>> {
        val pm = context.packageManager
        val query = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(query, 0)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .distinctBy { it.first }
            .sortedBy { it.second.lowercase() }
    }
}
