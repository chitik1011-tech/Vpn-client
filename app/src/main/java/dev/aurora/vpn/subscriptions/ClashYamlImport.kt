package dev.aurora.vpn.subscriptions

import dev.aurora.vpn.core.ServerProfile
import org.json.JSONObject
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

/** Import the proxy list from Clash / Mihomo YAML without running YAML custom constructors. */
object ClashYamlImport {
    private fun value(map: Map<*, *>, vararg keys: String): String =
        keys.firstNotNullOfOrNull { map[it]?.toString() }.orEmpty()

    private fun flag(value: Any?): Boolean = value?.toString()?.equals("true", true) == true

    fun parse(document: String, source: String = ""): List<ServerProfile> {
        require(document.length <= 2 * 1024 * 1024) { "Subscription too large" }
        val opts = LoaderOptions().apply {
            maxAliasesForCollections = 8
            nestingDepthLimit = 30
            codePointLimit = 2 * 1024 * 1024
            isAllowDuplicateKeys = false
        }
        val root = Yaml(SafeConstructor(opts)).load<Any>(document) as? Map<*, *>
            ?: throw IllegalArgumentException("Not a Clash YAML configuration")
        val nodes = root["proxies"] as? List<*>
            ?: throw IllegalArgumentException("No Clash proxies in subscription")
        require(nodes.size <= 3000) { "Too many proxy nodes" }
        val profiles = mutableListOf<ServerProfile>()
        for (entry in nodes) {
            val p = entry as? Map<*, *> ?: continue
            val type = value(p, "type").lowercase()
            if (type !in setOf("vless", "vmess", "trojan", "ss", "hysteria2", "hy2")) continue
            try {
                require(!flag(p["skip-cert-verify"])) { "Insecure TLS is forbidden" }
                val server = value(p, "server")
                val port = value(p, "port").toInt()
                val outType = when (type) {
                    "ss" -> "shadowsocks"
                    "hy2" -> "hysteria2"
                    else -> type
                }
                val outbound = JSONObject().put("type", outType).put("server", server)
                    .put("server_port", port)
                when (outType) {
                    "vless" -> {
                        outbound.put("uuid", value(p, "uuid"))
                        value(p, "flow").takeIf { it.isNotBlank() }?.let { outbound.put("flow", it) }
                    }
                    "vmess" -> {
                        outbound.put("uuid", value(p, "uuid"))
                            .put("security", value(p, "cipher").ifBlank { "auto" })
                            .put("alter_id", value(p, "alterId", "alter-id").ifBlank { "0" }.toInt())
                    }
                    "trojan", "hysteria2" -> outbound.put("password", value(p, "password"))
                    "shadowsocks" -> {
                        require(value(p, "plugin").isBlank()) { "Unsupported Shadowsocks plugin" }
                        outbound.put("method", value(p, "cipher"))
                            .put("password", value(p, "password"))
                    }
                }
                val reality = p["reality-opts"] as? Map<*, *>
                val tls = outType in setOf("trojan", "hysteria2") ||
                    flag(p["tls"]) || reality != null
                if (tls) {
                    val t = JSONObject().put("enabled", true)
                        .put("server_name", value(p, "servername", "sni", "peer").ifBlank { server })
                    val fingerprint = value(p, "client-fingerprint", "fingerprint")
                    if (fingerprint.isNotBlank()) t.put("utls", JSONObject()
                        .put("enabled", true).put("fingerprint", fingerprint))
                    if (reality != null) {
                        t.put("reality", JSONObject().put("enabled", true)
                            .put("public_key", value(reality, "public-key"))
                            .put("short_id", value(reality, "short-id")))
                    }
                    outbound.put("tls", t)
                }
                val network = value(p, "network").ifBlank { "tcp" }.lowercase()
                when (network) {
                    "tcp", "raw" -> Unit
                    "ws" -> {
                        val ws = p["ws-opts"] as? Map<*, *> ?: emptyMap<Any, Any>()
                        val t = JSONObject().put("type", "ws")
                            .put("path", value(ws, "path").ifBlank { "/" })
                        val headers = ws["headers"] as? Map<*, *>
                        val host = headers?.let { value(it, "Host", "host") }.orEmpty()
                        if (host.isNotBlank()) t.put("headers", JSONObject().put("Host", host))
                        outbound.put("transport", t)
                    }
                    "grpc" -> {
                        val grpc = p["grpc-opts"] as? Map<*, *> ?: emptyMap<Any, Any>()
                        outbound.put("transport", JSONObject().put("type", "grpc")
                            .put("service_name", value(grpc, "grpc-service-name", "serviceName")))
                    }
                    else -> throw IllegalArgumentException("Unsupported network transport")
                }
                if (outType == "hysteria2") {
                    val obfs = value(p, "obfs")
                    if (obfs.isNotBlank()) {
                        require(obfs == "salamander") { "Unsupported Hysteria2 obfs" }
                        outbound.put("obfs", JSONObject().put("type", "salamander")
                            .put("password", value(p, "obfs-password")))
                    }
                }
                profiles += ProxyLinkParser.fromOutbound(
                    value(p, "name").ifBlank { server }, outbound, source
                )
            } catch (_: IllegalArgumentException) {
                // Malformed/unsupported nodes do not hide other valid servers.
            } catch (_: org.json.JSONException) {
                // Do not expose node credentials or malformed values in errors.
            }
        }
        require(profiles.isNotEmpty()) { "No supported Clash proxies found" }
        return profiles.distinctBy { it.id }
    }
}
