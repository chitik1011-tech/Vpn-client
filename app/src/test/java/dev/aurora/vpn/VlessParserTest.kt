package dev.aurora.vpn

import dev.aurora.vpn.core.ServerProfile
import dev.aurora.vpn.core.SingBoxConfig
import dev.aurora.vpn.core.VlessParser
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class VlessParserTest {
    private val valid =
        "vless://11111111-2222-3333-4444-555555555555@vpn.example.org:443" +
        "?encryption=none&security=reality&sni=cdn.example.org&pbk=ABCDEF&sid=12ab" +
        "&fp=chrome&flow=xtls-rprx-vision&type=tcp#Test%20Server"

    @Test fun realityFields() {
        val endpoint = VlessParser.parse(valid)
        assertEquals("Test Server", endpoint.name)
        assertEquals("cdn.example.org", endpoint.sni)
        assertEquals("reality", endpoint.security)
        assertEquals("xtls-rprx-vision", endpoint.flow)
    }

    @Test fun singboxConfigContainsRealTunAndReality() {
        val root = JSONObject(SingBoxConfig.build(VlessParser.profile(valid)))
        val tun = root.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("tun", tun.getString("type"))
        assertTrue(tun.getBoolean("auto_route"))
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("vless", outbound.getString("type"))
        assertTrue(outbound.getJSONObject("tls").getJSONObject("reality").getBoolean("enabled"))
        assertEquals("proxy", root.getJSONObject("route").getString("final"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun invalidUuidRejected() {
        VlessParser.parse(valid.replace("11111111-2222-3333-4444-555555555555", "not-a-uuid"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun realityWithoutPublicKeyRejected() {
        VlessParser.parse(valid.replace("&pbk=ABCDEF", ""))
    }

    @Test(expected = IllegalArgumentException::class)
    fun insecureTlsRejected() {
        VlessParser.parse(valid + "&allowInsecure=true")
    }

    @Test(expected = IllegalArgumentException::class)
    fun unknownTransportRejected() {
        VlessParser.parse(valid.replace("type=tcp", "type=xhttp"))
    }

    @Test fun ipv6AndWebSocket() {
        val uri = "vless://11111111-2222-3333-4444-555555555555@[2001:db8::1]:443" +
            "?security=tls&type=ws&path=%2Ffoo&host=front.example#IPV6"
        val endpoint = VlessParser.parse(uri)
        assertEquals("2001:db8::1", endpoint.server)
        assertEquals("ws", endpoint.transport)
        assertEquals("/foo", endpoint.path)
        assertTrue(SingBoxConfig.build(ServerProfile.create("ipv6", uri)).contains("front.example"))
    }

    @Test fun stableIdentifiers() {
        val p = VlessParser.profile(valid)
        assertEquals(p.id, VlessParser.profile(valid).id)
        assertEquals(24, p.id.length)
    }
}
