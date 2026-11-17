package dev.aurora.vpn.subscriptions

import dev.aurora.vpn.core.ServerProfile
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.net.URI
import java.util.concurrent.TimeUnit

class SubscriptionImporter {
    companion object { private const val MAX_BYTES = 2 * 1024 * 1024 }

    private val client = OkHttpClient.Builder()
        .connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .followRedirects(true).followSslRedirects(false).build()

    fun parseContent(raw: String, source: String = ""): List<ServerProfile> {
        require(raw.length <= MAX_BYTES) { "Subscription is too large" }
        val input = raw.trim().removePrefix("\uFEFF").trim()
        require(input.isNotBlank()) { "Subscription is empty" }
        require(!input.startsWith("<!DOCTYPE", true) && !input.startsWith("<html", true)) {
            "Provider returned HTML instead of a subscription"
        }

        val text = when {
            input.startsWith("{") || input.startsWith("[") -> input
            input.startsWith("proxies:") || input.startsWith("proxy-providers:") -> input
            input.lineSequence().any { ProxyLinkParser.isShareLink(it.trim()) } -> input
            else -> runCatching { ProxyLinkParser.decodeBase64(input) }.getOrDefault(input).trim()
        }

        if (text.startsWith("{") || text.startsWith("[")) {
            return runCatching { SingBoxJsonImport.parse(text, source) }
                .getOrElse { ClashYamlImport.parse(text, source) }
        }
        if (text.startsWith("proxies:") || text.startsWith("proxy-providers:") ||
            text.lineSequence().take(20).any { it.trimStart().startsWith("proxies:") }) {
            return ClashYamlImport.parse(text, source)
        }
        val links = text.lineSequence().map { it.trim() }
            .filter { it.isNotBlank() && !it.startsWith("#") }.toList()
        require(links.size <= 3000) { "Too many nodes" }
        val profiles = links.mapNotNull { line ->
            if (ProxyLinkParser.isShareLink(line)) {
                runCatching { ProxyLinkParser.parse(line, source) }.getOrNull()
            } else null
        }
        require(profiles.isNotEmpty()) {
            "No supported nodes (VLESS, VMess, Trojan, Shadowsocks or Hysteria2)"
        }
        return profiles.distinctBy { it.id }
    }

    private fun get(url: String, agent: String): String {
        val request = Request.Builder().url(url)
            .header("Accept", "*/*")
            .header("User-Agent", agent)
            .build()
        client.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "Subscription HTTP status " + response.code }
            check(response.request.url.isHttps) { "HTTPS redirect required" }
            val stream = response.body?.byteStream() ?: error("Subscription returned no data")
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val n = stream.read(buffer)
                if (n < 0) break
                check(out.size() + n <= MAX_BYTES) { "Subscription exceeds 2 MiB" }
                out.write(buffer, 0, n)
            }
            return out.toString(Charsets.UTF_8.name())
        }
    }

    fun download(url: String): List<ServerProfile> {
        val parsed = URI(url.trim())
        require(parsed.scheme.equals("https", true) && parsed.host != null) {
            "Only HTTPS subscriptions are supported"
        }
        require(parsed.userInfo == null) { "Credentials in subscription URL are unsupported" }

        // Providers frequently choose an entirely different format based on User-Agent.
        // Retry format negotiation only if the content was downloaded but not parseable.
        var lastError: Exception? = null
        for (agent in listOf("Happ/2.0", "ClashMeta/1.0", "sing-box/1.14.0")) {
            val body = get(url, agent)
            try {
                return parseContent(body, url)
            } catch (e: IllegalArgumentException) {
                lastError = e
            } catch (e: org.json.JSONException) {
                lastError = e
            }
        }
        throw IllegalArgumentException(
            "No compatible proxy nodes in provider subscription",
            lastError
        )
    }
}
