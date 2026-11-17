package dev.aurora.vpn.subscriptions

import dev.aurora.vpn.core.ServerProfile
import dev.aurora.vpn.core.VlessParser
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Share-link decoding. The normalized sing-box outbound is stored in the encrypted profile vault. */
object ProxyLinkParser {
    private val supported = setOf("vless", "vmess", "trojan", "shadowsocks", "hysteria2")
    private val hostname = Regex("^[^\\s/@?#]+$")
    private fun decode(value: String): String =
        URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8.name())

    fun decodeBase64(value: String): String {
        val clean = value.trim().replace("\n", "").replace("\r", "")
            .replace('-', '+').replace('_', '/')
        require(clean.length < 3 * 1024 * 1024) { "Encoded subscription too large" }
        val padded = clean.padEnd((clean.length + 3) / 4 * 4, '=')
        return String(Base64.getDecoder().decode(padded), Charsets.UTF_8)
    }

    fun isShareLink(value: String): Boolean = listOf(
        "vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://"
    ).any { value.startsWith(it, ignoreCase = true) }

    private fun options(uri: URI): Map<String, String> =
        (uri.rawQuery ?: "").split("&").filter { it.isNotBlank() }.associate { item ->
            val chunks = item.split("=", limit = 2)
            decode(chunks[0]).lowercase() to decode(chunks.getOrElse(1) { "" })
        }

    private fun stringParam(params: Map<String, String>, vararg names: String): String =
        names.firstNotNullOfOrNull { params[it] }.orEmpty()

    private fun tls(params: Map<String, String>, server: String, force: Boolean): JSONObject? {
        require(stringParam(params, "allowinsecure", "insecure", "skip-cert-verify") !in listOf("1", "true")) {
            "Insecure TLS is not supported"
        }
        val security = stringParam(params, "security").lowercase()
        val needsTls = force || security == "tls" || security == "reality"
        if (!needsTls) return null
        val obj = JSONObject().put("enabled", true)
            .put("server_name", stringParam(params, "sni", "peer").ifBlank { server })
        val fingerprint = stringParam(params, "fp", "fingerprint")
        if (fingerprint.isNotBlank()) {
            obj.put("utls", JSONObject().put("enabled", true).put("fingerprint", fingerprint))
        }
        if (security == "reality") {
            val key = stringParam(params, "pbk", "publickey")
            require(key.isNotBlank()) { "REALITY public key missing" }
            obj.put("reality", JSONObject().put("enabled", true).put("public_key", key)
                .put("short_id", stringParam(params, "sid", "shortid")))
        }
        return obj
    }

    private fun transport(params: Map<String, String>): JSONObject? {
        val type = stringParam(params, "type", "network").ifBlank { "tcp" }.lowercase()
        return when (type) {
            "tcp", "raw" -> null
            "ws", "websocket" -> {
                val ws = JSONObject().put("type", "ws")
                    .put("path", stringParam(params, "path").ifBlank { "/" })
                val host = stringParam(params, "host")
                if (host.isNotEmpty()) ws.put("headers", JSONObject().put("Host", host))
                ws
            }
            "grpc" -> JSONObject().put("type", "grpc")
                .put("service_name", stringParam(params, "servicename", "service_name"))
            else -> error("Unsupported transport")
        }
    }

    fun parse(link: String, source: String = ""): ServerProfile {
        val text = link.trim()
        require(text.length in 10..16384) { "Invalid proxy link" }
        if (text.startsWith("vless://", true)) return VlessParser.profile(text, source)
        if (text.startsWith("vmess://", true)) {
            val raw = text.substringAfter("://").substringBefore("#")
            val v = JSONObject(decodeBase64(raw))
            require(v.optString("v") in listOf("", "2")) { "Unsupported VMess link" }
            require(v.optInt("aid", 0) == 0) { "Legacy VMess alterId is not supported" }
            val server = v.getString("add")
            val port = v.get("port").toString().toInt()
            val uuid = v.getString("id")
            val outbound = JSONObject().put("type", "vmess")
                .put("server", server).put("server_port", port).put("uuid", uuid)
                .put("security", v.optString("scy", "auto").ifBlank { "auto" })
                .put("alter_id", 0)
            val p = linkedMapOf(
                "type" to v.optString("net", "tcp"),
                "path" to v.optString("path", ""),
                "host" to v.optString("host", "")
            )
            val tlsMode = v.optString("tls", "").lowercase()
            if (tlsMode == "tls") {
                p["security"] = "tls"
                p["sni"] = v.optString("sni", "")
                p["fp"] = v.optString("fp", "")
            } else require(tlsMode.isBlank() || tlsMode == "none") { "Unsupported VMess TLS" }
            transport(p)?.let { outbound.put("transport", it) }
            tls(p, server, false)?.let { outbound.put("tls", it) }
            return fromOutbound(v.optString("ps", server), outbound, source)
        }
        if (text.startsWith("ss://", true)) return shadowsocks(text, source)
        val uri = URI(text)
        val type = uri.scheme?.lowercase() ?: error("Invalid proxy link")
        require(type in setOf("trojan", "hysteria2", "hy2")) { "Unsupported proxy protocol" }
        val server = uri.host ?: error("Server address missing")
        val port = uri.port
        val password = decode(uri.rawUserInfo ?: "")
        require(password.isNotBlank()) { "Proxy password missing" }
        val params = options(uri)
        val outbound = JSONObject().put("type", if (type == "trojan") "trojan" else "hysteria2")
            .put("server", server).put("server_port", port).put("password", password)
        if (type != "trojan") {
            val obfs = stringParam(params, "obfs")
            if (obfs.isNotBlank()) {
                require(obfs == "salamander") { "Unsupported Hysteria2 obfuscation" }
                outbound.put("obfs", JSONObject().put("type", "salamander")
                    .put("password", stringParam(params, "obfs-password")))
            }
        } else transport(params)?.let { outbound.put("transport", it) }
        tls(params, server, true)?.let { outbound.put("tls", it) }
        return fromOutbound(decode(uri.rawFragment ?: "").ifBlank { server }, outbound, source)
    }

    private fun shadowsocks(text: String, source: String): ServerProfile {
        val noScheme = text.substringAfter("://")
        val encodedPart = noScheme.substringBefore("#").substringBefore("?")
        val raw = if (!encodedPart.contains("@")) {
            decodeBase64(encodedPart)
        } else {
            val user = encodedPart.substringBefore("@")
            val credentials = if (user.contains(":")) user else decodeBase64(user)
            credentials + "@" + encodedPart.substringAfter("@")
        }
        val at = raw.lastIndexOf('@')
        require(at > 0) { "Invalid Shadowsocks credentials" }
        val credential = raw.substring(0, at)
        val colon = credential.indexOf(':')
        require(colon > 0) { "Invalid Shadowsocks method" }
        val method = decode(credential.substring(0, colon))
        val password = decode(credential.substring(colon + 1))
        val serverUri = URI("ss://" + raw.substring(at + 1))
        val server = serverUri.host ?: error("Shadowsocks server missing")
        require(password.isNotEmpty()) { "Shadowsocks password missing" }
        val outbound = JSONObject().put("type", "shadowsocks")
            .put("server", server).put("server_port", serverUri.port)
            .put("method", method).put("password", password)
        val name = decode(text.substringAfter("#", "")).ifBlank { server }
        require(!text.contains("plugin=", true)) { "Shadowsocks plugins are not supported" }
        return fromOutbound(name, outbound, source)
    }

    fun fromOutbound(name: String, sourceOutbound: JSONObject, source: String = ""): ServerProfile {
        val type = sourceOutbound.getString("type").lowercase()
        require(type in supported) { "Unsupported protocol" }
        val server = sourceOutbound.getString("server")
        val port = sourceOutbound.getInt("server_port")
        require(server.length in 1..255 && hostname.matches(server)) { "Invalid proxy host" }
        require(port in 1..65535) { "Invalid proxy port" }

        val out = JSONObject().put("type", type).put("server", server).put("server_port", port)
        when (type) {
            "vless" -> {
                out.put("uuid", sourceOutbound.getString("uuid"))
                VlessParser.parse("vless://" + sourceOutbound.getString("uuid") + "@example.org:443")
                val flow = sourceOutbound.optString("flow", "")
                if (flow.isNotEmpty()) out.put("flow", flow)
            }
            "vmess" -> {
                out.put("uuid", sourceOutbound.getString("uuid"))
                out.put("security", sourceOutbound.optString("security", "auto").ifBlank { "auto" })
                out.put("alter_id", sourceOutbound.optInt("alter_id", 0))
                require(out.getInt("alter_id") == 0) { "Legacy VMess not supported" }
            }
            "trojan", "hysteria2" -> {
                require(sourceOutbound.getString("password").isNotBlank()) { "Missing password" }
                out.put("password", sourceOutbound.getString("password"))
                if (type == "hysteria2") {
                    sourceOutbound.optJSONObject("obfs")?.let { obfs ->
                        require(obfs.optString("type") == "salamander") { "Unsupported obfuscation" }
                        out.put("obfs", JSONObject().put("type", "salamander")
                            .put("password", obfs.getString("password")))
                    }
                }
            }
            "shadowsocks" -> {
                out.put("method", sourceOutbound.getString("method"))
                out.put("password", sourceOutbound.getString("password"))
            }
        }
        sourceOutbound.optJSONObject("tls")?.let { tls ->
            require(!tls.optBoolean("insecure", false)) { "Insecure TLS is blocked" }
            val clean = JSONObject().put("enabled", tls.optBoolean("enabled", true))
                .put("server_name", tls.optString("server_name", server))
            tls.optJSONObject("utls")?.let { utls ->
                if (utls.optBoolean("enabled", true)) clean.put("utls", JSONObject()
                    .put("enabled", true).put("fingerprint", utls.optString("fingerprint", "chrome")))
            }
            tls.optJSONObject("reality")?.let { real ->
                if (real.optBoolean("enabled", true)) {
                    clean.put("reality", JSONObject().put("enabled", true)
                        .put("public_key", real.getString("public_key"))
                        .put("short_id", real.optString("short_id", "")))
                }
            }
            out.put("tls", clean)
        }
        sourceOutbound.optJSONObject("transport")?.let { transport ->
            val mode = transport.optString("type")
            val clean = when (mode) {
                "ws" -> JSONObject().put("type", "ws")
                    .put("path", transport.optString("path", "/"))
                "grpc" -> JSONObject().put("type", "grpc")
                    .put("service_name", transport.optString("service_name", ""))
                else -> error("Unsupported proxy transport")
            }
            if (mode == "ws") {
                transport.optJSONObject("headers")?.optString("Host", "")?.takeIf { it.isNotBlank() }
                    ?.let { clean.put("headers", JSONObject().put("Host", it)) }
            }
            out.put("transport", clean)
        }
        val payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(out.toString().toByteArray(Charsets.UTF_8))
        return ServerProfile.create(name.ifBlank { server }, "sb-outbound:" + payload, source, type.uppercase())
    }

    fun decodeOutbound(encoded: String): JSONObject {
        require(encoded.startsWith("sb-outbound:")) { "Unsupported native profile" }
        val raw = decodeBase64(encoded.removePrefix("sb-outbound:"))
        val obj = JSONObject(raw)
        val type = obj.optString("type")
        require(type in supported) { "Unsupported outbound" }
        return obj
    }
}
