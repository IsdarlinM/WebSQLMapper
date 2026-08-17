# Remote Web Console

WebSQLMapper keeps the Web UI loopback-only by default. Remote access is an explicit opt-in because the console can launch authorized security tests and display request/response evidence.

## Start a protected LAN/VPN console

```bash
websqlmapper web --host 0.0.0.0 --port 8787 --allow-remote
```

When no token is supplied, WebSQLMapper generates a strong random token and prints usable access URLs for the interfaces it can discover:

```text
WebSQLMapper web console · v0.4.2
Listening on 0.0.0.0:8787
Access URLs:
  http://127.0.0.1:8787/#token=wsm_...
  http://192.168.1.50:8787/#token=wsm_...
Web access token: wsm_...
```

The private link stores the token in the URL **fragment**. Browser fragments are not transmitted in the HTTP request. The UI consumes the token into session storage and removes the fragment from the address bar.

You can instead enter the printed token manually in the Remote Console bar.

## Custom token

Remote custom tokens must contain at least 16 characters:

```bash
websqlmapper web \
  --host 0.0.0.0 \
  --allow-remote \
  --token 'wsm_my_private_console_token'
```

API clients may authenticate with either:

```text
X-WebSQLMapper-Token: <token>
```

or:

```text
Authorization: Bearer <token>
```

Native browser `EventSource` cannot attach a custom authorization header, so query-token authentication is accepted **only** on `/api/jobs/<id>/events`. The server redacts that token from request logs.

## Trusted cross-origin API access

Direct WebSQLMapper UI usage is same-origin and needs no CORS configuration. If a trusted browser origin must call the API through a reverse-proxy/application setup, allow it explicitly:

```bash
websqlmapper web \
  --host 0.0.0.0 \
  --allow-remote \
  --allowed-origin 'https://console.example.test'
```

`--allowed-origin` is repeatable. WebSQLMapper validates each origin and responds to controlled CORS preflights only for explicitly configured origins.

## Network security

A direct `http://LAN-IP:8787` console is not encrypted. Use direct HTTP only on a trusted LAN/VPN. On an untrusted network, place WebSQLMapper behind an HTTPS reverse proxy and restrict network access to the intended operators.

Do not publish the remote console port directly to the public Internet unless you have separately implemented appropriate network-layer access controls.

## Troubleshooting

If another device cannot connect:

1. Confirm the server prints a non-loopback access URL.
2. Verify both devices can reach each other on the LAN/VPN.
3. Verify the host firewall permits inbound TCP on the selected port.
4. Avoid browsing to `0.0.0.0`; it is a bind address, not a client destination.
5. Confirm the console shows **remote connected** after entering the token.
6. If a reverse proxy is involved, ensure the browser Origin is same-origin with the console or add the exact trusted origin with `--allowed-origin`.

The public health endpoint is intentionally minimal and can be used to distinguish network reachability from token failures:

```text
GET /api/health
```

A reachable remote instance returns metadata such as `remote: true` and `token_required: true`. Protected endpoints return HTTP 401 until a valid token is supplied.
