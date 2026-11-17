package dev.aurora.vpn.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import dev.aurora.vpn.core.ServerProfile
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Android Keystore-backed AES-GCM; subscription URL and credentials never go to plain preferences. */
class SecretStore(private val context: Context) {
    private val prefs = context.getSharedPreferences("vault", Context.MODE_PRIVATE)
    private val alias = "aurora-vpn-profiles-v1"

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val found = store.getKey(alias, null)
        if (found is SecretKey) return found
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return generator.generateKey()
    }

    @Synchronized
    fun read(): List<ServerProfile> {
        val payload = prefs.getString("profiles", null) ?: return emptyList()
        val raw = Base64.decode(payload, Base64.NO_WRAP)
        require(raw.size > 12) { "Encrypted settings are invalid" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
        val array = JSONArray(String(cipher.doFinal(raw.copyOfRange(12, raw.size)), Charsets.UTF_8))
        return (0 until array.length()).map { i ->
            val item = array.getJSONObject(i)
            ServerProfile(
                item.getString("id"), item.getString("name"),
                item.getString("uri"), "VLESS", item.optString("subscription", "")
            )
        }
    }

    @Synchronized
    fun write(profiles: List<ServerProfile>) {
        require(profiles.size <= 3000) { "Too many profiles" }
        val items = JSONArray()
        profiles.forEach {
            items.put(JSONObject().put("id", it.id).put("name", it.name)
                .put("uri", it.uri).put("subscription", it.subscription))
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val bytes = cipher.iv + cipher.doFinal(items.toString().toByteArray(Charsets.UTF_8))
        check(prefs.edit().putString("profiles", Base64.encodeToString(bytes, Base64.NO_WRAP)).commit()) {
            "Could not save encrypted profiles"
        }
    }
}
