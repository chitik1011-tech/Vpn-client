# Engine and protocol status

Do not treat compilation as network verification.

| Protocol/feature | Status |
|---|---|
| sing-box libbox via Android VpnService | Implemented, Android hardware validation pending |
| VLESS + REALITY (TCP / Vision) | Implemented, real server validation pending |
| VLESS TLS | Implemented, real server validation pending |
| VLESS WebSocket | Implemented, real server validation pending |
| Xray-core | Not implemented |
| VMess / Trojan / Shadowsocks / HY2 / TUIC | Not implemented |
| Happ standard HTTPS subscription with VLESS links | Implemented, device validation pending |
| happ://add/ plaintext or base64 HTTPS wrapper | Implemented, tests added |
| sing-box JSON VLESS outbound import | Implemented, tests added |
| happ://crypt through crypt5 | Not implemented: private encrypted links require provider-supported authorization |
| Always-on and block-without-VPN | Provided by Android OS settings; device validation pending |

A successful APK build is not proof of tunneling. Verify on real Android:
1. Import valid VLESS + REALITY credentials for a controlled server.
2. Confirm Android permission dialog and active VPN indicator.
3. Confirm both TCP and UDP, DNS, IP route, external IPv4 and IPv6.
4. Test cellular/Wi-Fi switches, revoke and disconnect.
5. Capture packet traces on controlled server; check no DNS/IPv6 leak.
No tests requiring a real remote server have been performed in this environment.

DNS note: standard DNS is configured over the selected proxy (sing-box DoH detour). A distinct TLS-protected direct bootstrap lookup may be required to resolve the proxy host itself; until packet captures confirm, the project does not claim zero DNS leaks.
