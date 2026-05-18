# Django Channels + Daphne + Nginx + Saugra

This example routes both normal HTTP traffic and WebSocket traffic through
Saugra before the Django/Daphne upstream.

```txt
Client -> Nginx -> Saugra :8787 -> Daphne :8001 -> Django Channels
```

Start Daphne:

```bash
daphne -b 127.0.0.1 -p 8001 myproject.asgi:application
```

Start Saugra:

```bash
cargo run -- run --config examples/django-channels-daphne-nginx/saugra.yml
```

Install the Nginx snippet from `nginx.conf`, adjust `server_name`, then reload
Nginx.

Verification commands:

```bash
curl -i http://example.com/
curl -i "http://example.com/search?q=--"
curl -i \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Origin: https://example.com' \
  http://example.com/ws/chat/
```

Keep Django Channels authentication, channel authorization, and message-level
authorization enabled. Saugra protects the handshake and tunnels accepted
connections; it does not authorize every message sent after the upgrade.
