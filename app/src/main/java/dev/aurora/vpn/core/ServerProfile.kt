package dev.aurora.vpn.core

import java.security.MessageDigest

data class ServerProfile(
    val id: String,
    val name: String,
    val uri: String,
    val protocol: String = "VLESS",
    val subscription: String = ""
) {
    companion object {
        fun create(name: String, uri: String, subscription: String = "", protocol: String = "VLESS"): ServerProfile {
            val bytes = MessageDigest.getInstance("SHA-256").digest(uri.trim().toByteArray(Charsets.UTF_8))
            val id = bytes.take(12).joinToString("") { "%02x".format(it) }
            return ServerProfile(id, name.take(100), uri.trim(), protocol, subscription)
        }
    }
}
