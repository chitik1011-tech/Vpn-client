package dev.aurora.vpn.subscriptions

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Public, unencrypted Happ add links only; never attempts to decrypt crypt* links. */
object HappAdd {
    fun resolve(input: String): String {
        require(input.startsWith("happ://add/", ignoreCase = true)) { "Not a plain Happ add link" }
        val payload = input.substringAfter("happ://add/").trim()
        require(payload.length in 8..8192) { "Invalid add link" }
        val candidates = listOfNotNull(
            payload,
            runCatching { URLDecoder.decode(payload, StandardCharsets.UTF_8.name()) }.getOrNull(),
            runCatching { String(Base64.getUrlDecoder().decode(payload), Charsets.UTF_8) }.getOrNull(),
            runCatching { String(Base64.getDecoder().decode(payload), Charsets.UTF_8) }.getOrNull()
        )
        val url = candidates.firstOrNull { it.startsWith("https://", true) }
            ?: error("Plain Happ add link does not contain a valid HTTPS URL")
        val parsed = java.net.URI(url)
        require(parsed.scheme == "https" && parsed.host != null && parsed.userInfo == null) {
            "Happ subscription must be HTTPS"
        }
        return url
    }
}
