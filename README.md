# Aurora VPN — Android (экспериментальный проект)

**Статус: первый этап разработки. APK не собран, реальное подключение не подтверждено.**
Это независимый GPLv3-клиент, не связанный с Google, Happ и SagerNet.

## Что уже реализовано

- Kotlin + Jetpack Compose / Material 3 Dynamic Color, Android 8+ (API 26), ARM64.
- Настоящий Android VpnService с TUN FD и мостом libbox/ sing-box.
- Защита исходящих сокетов VpnService.protect(fd).
- Генерация конфигурации VLESS + TLS / REALITY / Vision / WebSocket.
- Импорт отдельных VLESS ссылок, обычной HTTPS или Base64 подписки, sing-box JSON только с VLESS.
- happ://add/ для открытых HTTPS ссылок, не для зашифрованных ссылок.
- Шифрование профилей AES-GCM с ключом Android Keystore.
- Экран сервера, запрос Android VPN permission, foreground service.
- GitHub Actions для compilation, tests, lint и debug APK.

## Сборка

Нужны Java 17, Android SDK 36, Build Tools 36.0.0 и Gradle 8.13.

```bash
gradle --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
```

Зависимость libbox AAR: `com.github.singbox-android:libbox:1.14.0`, JitPack. APK проверяется на `lib/arm64-v8a/libbox.so`.

**CI блокер:** workflow GitHub Actions пока завершает работу до назначения runner, без каких-либо шагов и логов. Код не компилировался. Нельзя считать статические исходники гарантией успешной установки или работы VPN.

## Проверка настоящего VPN

1. Нужен доступный VLESS+REALITY сервер с разрешёнными ключами.
2. Импортировать действительную ссылку; разрешить создание системного Android VPN.
3. Проверить активный TUN, затем TCP, UDP, DNS, IPv4 и IPv6 на сервере и устройстве.
4. Проверить Wi-Fi -> 4G, остановку, фон, отзыв разрешения, Always-on VPN.
5. Проверить маршрут DNS и IPv6 на утечки packet capture; гарантий защиты сейчас нет.

Переход в состояние CONNECTED означает лишь успешный старт движка и получение дескриптора TUN, а не подтверждённую доставку данных на удалённый сервер.

## Ограничения

- Xray-core и автоматический выбор движка не реализованы.
- VMess, Trojan, Shadowsocks, HY2, TUIC, WireGuard, OpenVPN, AmneziaWG не реализованы.
- `happ://crypt/`, `crypt2`, `crypt3`, `crypt4`, `crypt5` не поддержаны без доступных легальных ключей и API.
- QR-сканер, правила, настоящий ping/traffic counters, подписки с токенами/авторизацией, резервные сценарии и release signing не готовы.

Полная матрица — [docs/ENGINE_STATUS.md](docs/ENGINE_STATUS.md).
Лицензия — [LICENSE](LICENSE), упоминания авторов зависимостей — [NOTICE](NOTICE).

Рабочая ветка: `agent/android-vpn-foundation`, [PR #1](https://github.com/chitik1011-tech/Vpn-client/pull/1).
