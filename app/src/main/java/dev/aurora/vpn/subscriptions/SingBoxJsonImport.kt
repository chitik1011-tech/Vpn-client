package dev.aurora.vpn.subscriptions

import dev.aurora.vpn.core.ServerProfile
import org.json.JSONArray
import org.json.JSONObject

/** Extract only supported proxy outbounds; ignore DNS, routing and remote control configuration. */
object SingBoxJsonImport {
    fun parse(document: String, source: String = ""): List<ServerProfile> {
        require(document.length <= 2 * 1024 * 1024) { "JSON subscription too large" }
        val json = document.trim()
        val outbounds: JSONArray = if (json.startsWith("[")) JSONArray(json)
        else JSONObject(json).optJSONArray("outbounds")
            ?: throw IllegalArgumentException("Not a sing-box outbound list")
        require(outbounds.length() <= 3000) { "Too many outbounds" }
        val profiles = mutableListOf<ServerProfile>()
        for (i in 0 until outbounds.length()) {
            val raw = outbounds.optJSONObject(i) ?: continue
            val type = raw.optString("type")
            if (type !in setOf("vless", "vmess", "trojan", "shadowsocks", "hysteria2")) continue
            profiles += ProxyLinkParser.fromOutbound(
                raw.optString("tag").ifBlank { raw.optString("server", "Proxy") },
                raw, source
            )
        }
        require(profiles.isNotEmpty()) { "No supported proxy outbounds in JSON" }
        return profiles.distinctBy { it.id }
    }
}
