package dev.aurora.vpn.subscriptions

import dev.aurora.vpn.core.ServerProfile
import dev.aurora.vpn.core.VlessParser
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder

/** Strict conversion of supported sing-box VLESS outbounds to standard VLESS URI profiles. */
object SingBoxJsonImport {
    private fun escape(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    fun parse(document: String, source: String = ""): List<ServerProfile> {
        require(document.length <= 2 * 1024 * 1024) { "JSON too large" }
        val json = document.trim()
        val outbounds: JSONArray = if (json.startsWith("[")) {
            JSONArray(json)
        } else {
            val root = JSONObject(json)
            root.optJSONArray("outbounds")
                ?: throw IllegalArgumentException("No sing-box outbounds")
        }
        require(outbounds.length() <= 3000) { "Too many outbounds" }
        val profiles = mutableListOf<ServerProfile>()
        for (i in 0 until outbounds.length()) {
            val outbound = outbounds.getJSONObject(i)
            if (outbound.optString("type") != "vless") continue
            val host = outbound.getString("server")
            val port = outbound.getInt("server_port")
            val uuid = outbound.getString("uuid")
            val tls = outbound.optJSONObject("tls")
            val security = when {
                tls?.optJSONObject("reality")?.optBoolean("enabled") == true -> "reality"
                tls?.optBoolean("enabled") == true -> "tls"
                else -> "none"
            }
            val reality = tls?.optJSONObject("reality")
            val transport = outbound.optJSONObject("transport")
            val type = transport?.optString("type", "tcp") ?: "tcp"
            val params = linkedMapOf(
                "security" to security,
                "type" to type
            )
            if (tls != null) {
                params["sni"] = tls.optString("server_name", "")
                params["fp"] = tls.optJSONObject("utls")?.optString("fingerprint", "chrome") ?: "chrome"
            }
            if (reality != null) {
                params["pbk"] = reality.optString("public_key", "")
                params["sid"] = reality.optString("short_id", "")
            }
            val flow = outbound.optString("flow", "")
            if (flow.isNotEmpty()) params["flow"] = flow
            if (type == "ws" && transport != null) {
                params["path"] = transport.optString("path", "/")
                val wsHost = transport.optJSONObject("headers")?.optString("Host", "") ?: ""
                if (wsHost.isNotEmpty()) params["host"] = wsHost
            }
            val name = outbound.optString("tag", host).ifBlank { host }
            val authority = if (host.contains(":") && !host.startsWith("[")) "[$host]" else host
            val link = "vless://" + uuid + "@" + authority + ":" + port + "?" +
                params.entries.joinToString("&") { escape(it.key) + "=" + escape(it.value) } +
                "#" + escape(name)
            val parsed = VlessParser.profile(link, source)
            profiles += parsed
        }
        require(profiles.isNotEmpty()) { "No supported VLESS outbounds in JSON" }
        return profiles.distinctBy { it.id }
    }
}
