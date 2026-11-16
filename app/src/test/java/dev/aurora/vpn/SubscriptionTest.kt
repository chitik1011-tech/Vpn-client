package dev.aurora.vpn

import dev.aurora.vpn.subscriptions.HappAdd
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
        assertTrue(results[0].uri.startsWith("vless://"))
        assertTrue(results[0].uri.contains("security=reality"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun invalidJsonRejected() {
        SingBoxJsonImport.parse("""{"outbounds":[{"type":"vless","server":"bad"}]}""")
    }

    @Test(expected = IllegalArgumentException::class)
    fun unsupportedProtocolRejected() {
        SingBoxJsonImport.parse("""{"outbounds":[{"type":"trojan","server":"host"}]}""")
    }
}
