# Architecture: first functional slice

- \`MainActivity\`: Material You Compose UI, permission request, server picker, imports.
- \`ProfileRepository\`: in-memory observable view of encrypted at-rest profiles.
- \`SecretStore\`: Android Keystore AES-256-GCM; no secrets in Intent extras.
- \`VlessParser\`: validated VLESS URI parameters.
- \`SingBoxConfig\`: produces a real sing-box TUN inbound and VLESS outbound with TLS/REALITY.
- \`TunnelService\`: only VpnService implementation, foreground notification, lifecycle.
- \`AndroidPlatform\`: PlatformInterface callback to open Android TUN and protect outbound sockets.
- \`SubscriptionImporter\`: HTTPS standard VLESS/base64 subscriptions; 2 MiB hard cap.

The network path is \`VpnService.Builder.establish\` -> FD -> libbox TUN inbound -> sing-box outbound.
Android grants VPN permission explicitly and provides OS Always-on/block-without-VPN settings.
No mock native network code is present. Actual remote authentication still needs an Android device and a test server.

## Explicitly not yet implemented

Xray, Happ encrypted crypt formats, user authentication headers, QR scanner, background subscription refresh,
kill-switch outside OS Always-on VPN, per-app routing, multi-protocol parser, real stats and native ping.
The UI deliberately omits fake graphs, fake latency or fake traffic speeds.

## Sources

- https://github.com/SagerNet/sing-box-for-android
- https://github.com/SagerNet/sing-box/tree/testing/experimental/libbox
- https://github.com/singbox-android/libbox
- https://www.happ.su/main/dev-docs/crypto-link
