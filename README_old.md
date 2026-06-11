# Chardih's Frontend — Scraper Display

A standalone, display-only version of the `polymarket_derivative_test` frontend.
Trading is retired; this just shows the scrapers in action: a live BTC-USD chart
(Coinbase) side by side with the Polymarket 5-minute BTC up/down order book
(best bid/ask of the "Up" contract). The old paper-trades panel is kept at the
bottom for posterity, but it is **dead** — nothing in it updates, all buttons
are disabled, and the server has no trading code at all.

## Files

| File | Purpose |
|------|---------|
| `server.py` | The backend: Coinbase WS feed + Polymarket WS feed + aiohttp relay in one asyncio loop. Serves `index.html` at `/` and broadcasts ticks over `/ws`. |
| `security.py` | Security layer: argon2id Basic Auth + session cookies, brute-force lockout, rate limiting, security headers. All env-gated (see below). |
| `index.html` | The frontend. Clone of the original `live_btc_feed.html` with all trading JS removed. Charts, window controls, and header stats are fully live. |
| `hash_password.py` | Interactive helper: password → argon2id hash for `AUTH_PASSWORD_HASH`. |
| `gen_cert.py` | Helper: generates a self-signed RSA-4096 cert for IP-only HTTPS access. |
| `requirements.txt` | `aiohttp` + `websockets` (+ `argon2-cffi` for auth, `cryptography` for gen_cert). |

## Quick start (local, no security)

```bash
cd ~/chardihs_frontend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python server.py
# open http://localhost:8765
```

## Security architecture

**Threat model.** The server displays public-market data and accepts no
commands (the browser sends nothing; inbound WS messages are ignored and
chatty clients are dropped). The realistic risks when hosted online are:
unwanted public access, credentials/cookies in cleartext, password
brute-forcing, and resource exhaustion (connection floods). Each is addressed
by a layer below.

| Layer | What it does | How it's enabled |
|-------|--------------|------------------|
| **Authentication** | HTTP Basic Auth verified against an argon2id hash; timing-safe comparison on both username and password (no enumeration via timing). On success a 256-bit session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` under TLS) is issued; the `/ws` upgrade validates the cookie, since the browser WebSocket API cannot send an `Authorization` header. | Set `AUTH_PASSWORD_HASH` (run `hash_password.py`) |
| **TLS** | HTTPS/WSS terminated in-app. HSTS header sent when on. | Set `TLS_CERT` + `TLS_KEY` (run `gen_cert.py`, or use real certs) |
| **Brute-force lockout** | Per-IP sliding window over *failed* auth attempts: more than 5 failures in 15 minutes → 429 until the window drains. Credential-less first requests (the normal browser auth dance) don't count. | Always on (when auth is on) |
| **HTTP rate limit** | Per-IP cap of 60 requests/min on all non-WS endpoints → 429. | Always on |
| **Connection caps** | Max 50 concurrent WS clients total, max 5 per IP; refused before upgrade with 503/429. Inbound WS messages capped at 4 KB, clients sending >50 messages are dropped. | Always on |
| **Security headers** | CSP (self + inline, ws/wss connect), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, HSTS under TLS. | Always on |

The secrets are environment variables only — nothing sensitive lives in this
folder (the self-signed key in `certs/` is machine-local; don't commit it if
you ever git-init this).

### Environment variables

| Var | Default | Meaning |
|-----|---------|---------|
| `PORT` | `8765` | Listen port |
| `HOST` | `0.0.0.0` | Bind address — set `127.0.0.1` behind a reverse proxy |
| `AUTH_PASSWORD_HASH` | *(unset = no auth)* | argon2id hash from `hash_password.py` |
| `AUTH_USERNAME` | `admin` | Basic Auth username |
| `SESSION_TTL_HOURS` | `24` | Session cookie lifetime |
| `TLS_CERT`, `TLS_KEY` | *(unset = plain HTTP)* | PEM cert + key paths |
| `TRUST_PROXY` | off | `1` → trust `X-Forwarded-For` for client IPs (**only** behind a proxy you control — the header is spoofable otherwise) |
| `MAX_WS_CLIENTS` | `50` | Total concurrent browser connections |
| `MAX_WS_PER_IP` | `5` | Concurrent connections per IP |

### Hosting option A — reverse proxy with a real domain (recommended)

Run the app on localhost, let Caddy handle TLS (automatic Let's Encrypt, no
browser warnings) and proxy both HTTP and the WS upgrade:

```bash
# app
export HOST=127.0.0.1 TRUST_PROXY=1
export AUTH_PASSWORD_HASH='<from hash_password.py>'   # single quotes — hash contains $
python server.py
```

`Caddyfile`:

```
chardihs.example.com {
    reverse_proxy 127.0.0.1:8765
}
```

That's it — Caddy proxies WebSockets out of the box. `TRUST_PROXY=1` makes the
rate limiter and lockout see real client IPs instead of `127.0.0.1`, and marks
session cookies `Secure` even though the app itself speaks plain HTTP to the
proxy. Don't set `TLS_CERT`/`TLS_KEY` in this setup.

### Hosting option B — direct, IP-only (self-signed, like the old VPS)

```bash
.venv/bin/python gen_cert.py --ip <server-public-ip>
.venv/bin/python hash_password.py        # → export AUTH_PASSWORD_HASH='...'
export TLS_CERT=certs/server.crt TLS_KEY=certs/server.key
export AUTH_PASSWORD_HASH='...'
.venv/bin/python server.py
# open https://<server-ip>:8765, accept the cert warning (verify the fingerprint)
```

Known browser quirk from the original project: Firefox's captive-portal
detection can swallow the Basic Auth dialog with self-signed certs — use
Chrome/Edge or disable `network.captive-portal-service.enabled` in
`about:config`.

### Hosting option C — private, no public exposure

Run with no auth/TLS, bind to localhost, and SSH-tunnel in:

```bash
HOST=127.0.0.1 python server.py
# from your machine: ssh -L 8765:localhost:8765 user@host → http://localhost:8765
```

### systemd service (options A/B)

`/etc/systemd/system/chardihs-frontend.service`:

```ini
[Unit]
Description=Chardihs Frontend (scraper display)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=youruser
WorkingDirectory=/home/youruser/chardihs_frontend
EnvironmentFile=/etc/chardihs-frontend/secrets.env
ExecStart=/home/youruser/chardihs_frontend/.venv/bin/python server.py
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
```

`/etc/chardihs-frontend/secrets.env` (root:root, chmod 600 — `$` signs in the
argon2 hash are safe in an EnvironmentFile, no escaping needed):

```
AUTH_PASSWORD_HASH=$argon2id$v=19$m=65536,t=3,p=4$...
TLS_CERT=certs/server.crt
TLS_KEY=certs/server.key
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now chardihs-frontend
```

(Lesson from the original project: `StartLimitIntervalSec` belongs in `[Unit]`,
not `[Service]` — systemd silently ignores it otherwise.)

## Architecture

```
Coinbase WS (BTC-USD matches) ──► run_coinbase_feed ──► relay.broadcast()
                                                              │
Polymarket WS (book / best_bid_ask) ─► run_polymarket_feed ──►│
  (market discovery via Gamma API,                            ▼
   auto-rolls to a new market every            security middleware (auth/limits)
   5-min epoch, same as the original)                         │
                                                              ▼
                                                 browser clients on /ws
```

Compared to the original `run_scraper.py`: parquet/CSV writers, all five
paper/live traders, the trade-tick stream, `config.yaml`, clock-skew sampling,
and the Binance.us fallback were removed. The Polymarket discovery flow (slug
`btc-updown-5m-{epoch}` → Gamma `/events?slug=` → CLOB `/markets/{conditionId}`
→ WS subscribe), the reconnect/epoch-transition logic, and the argon2id
auth + session-cookie design were carried over.

### WebSocket message protocol (server → browser)

| Shape | Meaning |
|-------|---------|
| `{timestamp_ms, price, feed_type}` (no `type` field) | BTC-USD trade tick — drives the left chart, header price, TPS counter |
| `{type: "poly_bid", timestamp_ms, contract, best_bid}` | Polymarket best bid update (frontend plots `contract == "Up"` only) |
| `{type: "poly_ask", timestamp_ms, contract, best_ask}` | Polymarket best ask update |

The browser never sends anything meaningful back; the server ignores client
messages and drops clients that send too many.

## Behavior notes

- **"Waiting for data..."** on the Polymarket chart for a few seconds at
  startup and around each 5-minute epoch boundary is normal — the next market
  is resolved via the Gamma API as the epoch rolls.
- The dashed yellow **EPOCH** line on the BTC chart marks the BTC price at the
  start of the current 5-minute epoch — the strike the up/down market resolves
  against.
- On the right chart, blue is the Up contract's best bid, orange its best ask.
- Both feeds reconnect automatically with exponential backoff (1→16s); the
  retry counter resets after any connection that survived >60s.
- No data is written to disk. Charts keep up to 50k points in browser memory;
  refresh the page to clear.
- Console logging: startup/connection events, 60s Coinbase heartbeats, epoch
  transitions, client connects, auth failures/lockouts. Individual ticks are
  not logged.

## Provenance

Extracted 2026-06-10/11 from `polymarket_derivative_test` (commit `b2effde`
era): `scraper/binance_feed.py`, `scraper/polymarket_feed.py`,
`scraper/ws_relay.py`, `run_scraper.py`, `live_btc_feed.html`,
`scripts/hash_password.py`, and `scripts/gen_cert.py`, trimmed to display-only.
