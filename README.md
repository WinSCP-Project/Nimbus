# Nimbus

Клиент подписок в духе Happ / Incy: один бинарник, веб-интерфейс, ядро **sing-box**.

Подписки (URL), ручной импорт ссылок, Clash YAML, sing-box JSON. Протоколы: VLESS (Reality), VMess, Trojan, Shadowsocks, Hysteria / Hysteria2, TUIC, SOCKS, HTTP, WireGuard, AnyTLS.

## Запуск

```bash
go test ./...
go build -o nimbus .
./nimbus -listen 127.0.0.1:8787
```

UI: `http://127.0.0.1:8787`

Данные: `~/.nimbus/state.json`. При первом подключении Nimbus сам скачает `sing-box` в `~/.nimbus/bin/`.

Локальный прокси после Connect: mixed **10808** (SOCKS5 + HTTP).

## Флаги

| флаг | смысл |
|------|--------|
| `-data` | каталог состояния и ядра |
| `-listen` | адрес UI, перекрывает настройки |

## Маршрутизация

- **Правила** — private IP и часть CN-доменов напрямую, остальное в узел
- **Глобальный** — всё в узел
- **Прямой** — без прокси

TUN включается в настройках и требует прав администратора / root. Для обычной работы достаточно mixed-порта.

## API

- `GET /api/state`
- `POST /api/subscriptions` `{name,url,user_agent}`
- `POST /api/subscriptions/{id}/update`
- `DELETE /api/subscriptions/{id}`
- `POST /api/import` `{sub_id,text}`
- `POST /api/connect` `{id}`
- `POST /api/disconnect`
- `POST /api/ping-all`
- `GET /api/events` SSE
