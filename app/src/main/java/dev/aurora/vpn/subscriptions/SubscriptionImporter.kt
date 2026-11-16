package dev.aurora.vpn.subscriptions

import java.util.Base64
import dev.aurora.vpn.core.ServerProfile
import dev.aurora.vpn.core.VlessParser
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.net.URI
import java.util.concurrent.TimeUnit

class SubscriptionImporter {
    companion object { private const val MAX_BYTES = 2 * 1024 * 1024 }
    private val client = OkHttpClient.Builder().connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS).followRedirects(true).build()

    fun parseContent(raw: String, source: String = ""): List<ServerProfile> {
        require(raw.length <= MAX_BYTES) { "Subscription is too large" }
        val sourceText = raw.trim()
        if (sourceText.startsWith("{") || sourceText.startsWith("[")) {
            return SingBoxJsonImport.parse(sourceText, source)
        }
        val decoded = if (sourceText.startsWith("vless://") || sourceText.contains('\n')) {
            sourceText
        } else {
            runCatching {
                val fixed = sourceText.replace("\n", "").replace("\r", "")
                String(Base64.getMimeDecoder().decode(fixed), Charsets.UTF_8)
            }.getOrDefault(sourceText)
        }
        val lines = decoded.lineSequence().map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }.toList()
        require(lines.size <= 3000) { "Too many servers" }
        val parsed = lines.mapNotNull { line ->
            if (line.startsWith("vless://", ignoreCase = true)) {
                // Reject malformed individual links rather than silently accepting bad credentials.
                VlessParser.profile(line, source)
            } else null
        }.distinctBy { it.id }
        require(parsed.isNotEmpty()) { "No supported VLESS servers in subscription" }
        return parsed
    }

    fun download(url: String): List<ServerProfile> {
        val parsed = URI(url.trim())
        require(parsed.scheme == "https" && parsed.host != null) { "Only HTTPS subscriptions are allowed" }
        require(parsed.userInfo == null) { "Credentials in subscription URLs are not supported" }
        val request = Request.Builder().url(url).header("Accept", "text/plain, application/json").build()
        client.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "Subscription HTTP error " + response.code }
            check(response.request.url.isHttps) { "HTTPS redirect required" }
            val stream = response.body?.byteStream() ?: error("Missing subscription response")
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val n = stream.read(buffer)
                if (n < 0) break
                check(out.size() + n <= MAX_BYTES) { "Subscription size limit exceeded" }
                out.write(buffer, 0, n)
            }
            return parseContent(out.toString(Charsets.UTF_8.name()), url)
        }
    }
}
