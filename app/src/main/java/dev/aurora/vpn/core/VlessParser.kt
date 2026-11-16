package dev.aurora.vpn.core

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

data class VlessEndpoint(
    val uuid: String,
    val server: String,
    val port: Int,
    val name: String,
    val security: String,
    val sni: String,
    val publicKey: String,
    val shortId: String,
    val fingerprint: String,
    val flow: String,
    val transport: String,
    val path: String,
    val host: String
)

object VlessParser {
    private val uuidRegex = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    private fun decode(text: String) = URLDecoder.decode(text.replace("+", "%2B"), StandardCharsets.UTF_8.name())

    fun parse(link: String): VlessEndpoint {
        require(link.length in 15..16384) { "Invalid VLESS link length" }
        val uri = URI(link.trim())
        require(uri.scheme.equals("vless", ignoreCase = true)) { "Only VLESS URI is supported" }
        val uuid = decode(uri.rawUserInfo ?: "")
        require(uuidRegex.matches(uuid)) { "Invalid VLESS UUID" }
        val host = uri.host?.trim('[', ']') ?: throw IllegalArgumentException("Missing VLESS server")
        require(host.isNotBlank() && host.length <= 255) { "Invalid server host" }
        val port = uri.port
        require(port in 1..65535) { "Invalid server port" }
        val params = (uri.rawQuery ?: "").split('&').filter { it.isNotBlank() }.associate {
            val parts = it.split('=', limit = 2)
            decode(parts[0]) to decode(parts.getOrElse(1) { "" })
        }
        require((params["encryption"] ?: "none") == "none") { "VLESS encryption must be none" }
        val security = params["security"] ?: "none"
        require(security in setOf("reality", "tls", "none")) { "Unsupported security: $security" }
        val transport = params["type"] ?: "tcp"
        require(transport in setOf("tcp", "raw", "ws")) { "Unsupported transport: $transport" }
        val sni = params["sni"].orEmpty()
        val publicKey = params["pbk"].orEmpty()
        if (security == "reality") {
            require(sni.isNotEmpty() && publicKey.isNotEmpty()) { "REALITY requires SNI and public key" }
        }
        require(params["allowInsecure"] != "1" && params["allowInsecure"] != "true") {
            "TLS certificate bypass is disabled"
        }
        val name = uri.rawFragment?.let(::decode)?.take(100)?.ifBlank { null } ?: host
        return VlessEndpoint(
            uuid = uuid, server = host, port = port, name = name,
            security = security, sni = sni, publicKey = publicKey,
            shortId = params["sid"].orEmpty(),
            fingerprint = params["fp"].orEmpty().ifBlank { "chrome" },
            flow = params["flow"].orEmpty(),
            transport = transport, path = params["path"].orEmpty().ifBlank { "/" },
            host = params["host"].orEmpty()
        )
    }

    fun profile(link: String, subscription: String = ""): ServerProfile {
        val endpoint = parse(link)
        return ServerProfile.create(endpoint.name, link, subscription)
    }
}
