package dev.aurora.vpn.core

import dev.aurora.vpn.subscriptions.ProxyLinkParser
import org.json.JSONArray
import org.json.JSONObject

object SingBoxConfig {
    fun build(profile: ServerProfile): String {
        val outbound = if (profile.uri.startsWith("sb-outbound:")) {
            ProxyLinkParser.decodeOutbound(profile.uri)
        } else {
            val s = VlessParser.parse(profile.uri)
            JSONObject()
            .put("domain_resolver", "bootstrap")
            .put("type", "vless")
            .put("tag", "proxy")
            .put("server", s.server)
            .put("server_port", s.port)
            .put("uuid", s.uuid)

        if (s.flow.isNotEmpty()) {
            require(s.flow == "xtls-rprx-vision") { "Unsupported VLESS flow" }
            outbound.put("flow", s.flow)
        }
        if (s.security != "none") {
            val tls = JSONObject()
                .put("enabled", true)
                .put("server_name", s.sni.ifBlank { s.server })
                .put("utls", JSONObject().put("enabled", true).put("fingerprint", s.fingerprint))
            if (s.security == "reality") {
                tls.put("reality", JSONObject().put("enabled", true)
                    .put("public_key", s.publicKey).put("short_id", s.shortId))
            }
            outbound.put("tls", tls)
        }
        if (s.transport == "ws") {
            val transport = JSONObject().put("type", "ws").put("path", s.path)
            if (s.host.isNotEmpty()) transport.put("headers", JSONObject().put("Host", s.host))
            outbound.put("transport", transport)
        }

        }
        outbound.put("domain_resolver", "bootstrap").put("tag", "proxy")

        // TUN FD is requested by libbox through PlatformInterface.openTun().
        // The Android VPN is not established manually or represented by a mock socket.
        val tun = JSONObject().put("type", "tun").put("tag", "tun-in")
            .put("address", JSONArray().put("172.19.0.1/30").put("fdfe:dcba:9876::1/126"))
            .put("mtu", 1500).put("auto_route", true).put("stack", "mixed")
            .put("dns_mode", "hijack")
        val dns = JSONObject().put("servers",
            JSONArray().put(JSONObject().put("type", "https").put("tag", "remote")
                .put("server", "1.1.1.1").put("server_port", 443).put("detour", "proxy"))
                .put(JSONObject().put("type", "https").put("tag", "bootstrap")
                .put("server", "9.9.9.9").put("server_port", 443).put("detour", "direct")))
            .put("final", "remote")
        return JSONObject()
            .put("log", JSONObject().put("level", "warn"))
            .put("dns", dns)
            .put("inbounds", JSONArray().put(tun))
            .put("outbounds", JSONArray().put(outbound).put(JSONObject().put("type", "direct").put("tag", "direct")))
            .put("route", JSONObject().put("final", "proxy").put("auto_detect_interface", true))
            .toString()
    }
}
