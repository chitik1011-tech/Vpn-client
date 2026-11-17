package dev.aurora.vpn

import dev.aurora.vpn.subscriptions.HappAdd
import dev.aurora.vpn.subscriptions.ProxyLinkParser
import dev.aurora.vpn.subscriptions.ClashYamlImport
import dev.aurora.vpn.subscriptions.SingBoxJsonImport
import dev.aurora.vpn.subscriptions.SubscriptionImporter
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class SubscriptionTest {
    private val link = "vless://11111111-2222-3333-4444-555555555555@vpn.example.org:443" +
        "?security=reality&sni=cdn.example.org&pbk=PUBLIC&sid=ff#A"

    @Test fun standardLinkSubscription() {
        val profiles = SubscriptionImporter().parseContent(link + "\n" + link, "https://example.org/sub")
        assertEquals(1, profiles.size)
        assertEquals("https://example.org/sub", profiles[0].subscription)
    }

    @Test fun base64Subscription() {
        val encoded = Base64.getEncoder().encodeToString(link.toByteArray(Charsets.UTF_8))
        assertEquals(1, SubscriptionImporter().parseContent(encoded).size)
    }

    @Test fun publicHappAddLink() {
        val plain = "happ://add/https://sub.example.org/path?token=demo"
        assertEquals("https://sub.example.org/path?token=demo", HappAdd.resolve(plain))
    }

    @Test fun base64HappAddLink() {
        val address = "https://sub.example.org/private"
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(address.toByteArray())
        assertEquals(address, HappAdd.resolve("happ://add/" + encoded))
    }

    @Test(expected = IllegalArgumentException::class)
    fun noEncryptedHappBypass() {
        HappAdd.resolve("happ://crypt5/opaque")
    }

    @Test fun singboxJsonToVlessUri() {
        val json = """{"outbounds":[{"type":"direct","tag":"direct"},{"type":"vless",
            "tag":"test","server":"edge.example.org","server_port":443,
            "uuid":"11111111-2222-3333-4444-555555555555",
            "tls":{"enabled":true,"server_name":"cdn.example.org",
                "reality":{"enabled":true,"public_key":"PUBLIC","short_id":"ff"}}}]}"""
        val results = SingBoxJsonImport.parse(json)
        assertEquals(1, results.size)
        assertEquals("VLESS", results[0].protocol)
        assertTrue(results[0].uri.startsWith("sb-outbound:"))
        assertTrue(ProxyLinkParser.decodeOutbound(results[0].uri).getJSONObject("tls").has("reality"))
    }


    @Test fun clashYamlVlessAndTrojan() {
        val input = """
            proxies:
              - name: "Test Reality"
                type: vless
                server: edge.example.net
                port: 443
                uuid: 11111111-2222-3333-4444-555555555555
                tls: true
                servername: example.net
                reality-opts:
                  public-key: PUBKEY
                  short-id: abc
              - name: "Fallback"
                type: trojan
                server: trojan.example.net
                port: 443
                password: secret
                sni: cdn.example.net
        """.trimIndent()
        val profiles = SubscriptionImporter().parseContent(input, "https://example.org/sub")
        assertEquals(2, profiles.size)
        assertEquals("TROJAN", profiles[1].protocol)
        assertEquals("trojan", ProxyLinkParser.decodeOutbound(profiles[1].uri).getString("type"))
    }

    @Test fun base64MixedSubscription() {
        val trojan = "trojan://password@example.org:443?sni=example.org#Example"
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(
            (link + "\n" + trojan).toByteArray()
        )
        val profiles = SubscriptionImporter().parseContent(encoded)
        assertEquals(2, profiles.size)
        assertEquals("TROJAN", profiles[1].protocol)
    }

    @Test fun vmessJsonShareLink() {
        val doc = """{"v":"2","ps":"VMess Node","add":"edge.example.org","port":"443",
          "id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto",
          "net":"ws","path":"/proxy","host":"cdn.example.org","tls":"tls"}"""
        val link = "vmess://" + Base64.getEncoder().encodeToString(doc.toByteArray())
        val profile = ProxyLinkParser.parse(link)
        assertEquals("VMESS", profile.protocol)
        val outbound = ProxyLinkParser.decodeOutbound(profile.uri)
        assertEquals("vmess", outbound.getString("type"))
        assertEquals("ws", outbound.getJSONObject("transport").getString("type"))
    }

    @Test fun shadowsocksSIP002() {
        val creds = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("aes-256-gcm:password".toByteArray())
        val profile = ProxyLinkParser.parse("ss://" + creds + "@edge.example.org:8388#SS")
        assertEquals("SHADOWSOCKS", profile.protocol)
    }

    @Test(expected = IllegalArgumentException::class)
    fun skipInsecureClashProxy() {
        ClashYamlImport.parse("""
            proxies:
              - name: unsafe
                type: trojan
                server: proxy.example.org
                port: 443
                password: x
                skip-cert-verify: true
        """.trimIndent())
    }

    @Test(expected = org.json.JSONException::class)
    fun invalidJsonRejected() {
        SingBoxJsonImport.parse("""{"outbounds":[{"type":"vless","server":"bad"}]}""")
    }

    @Test(expected = org.json.JSONException::class)
    fun missingTrojanRequiredFieldsRejected() {
        SingBoxJsonImport.parse("""{"outbounds":[{"type":"trojan","server":"host"}]}""")
    }
}
