import asyncio
import json
import logging
import os
import signal
import ssl
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import aiohttp
import websockets
from aiohttp import web

from security import (
    Authenticator,
    SessionStore,
    client_ip,
    make_security_middleware,
)

logger = logging.getLogger("chardihs_frontend")

# constants. No config file

DEFAULT_PORT = 8765
DEFAULT_MAX_WS_CLIENTS = 50
DEFAULT_MAX_WS_PER_IP = 5

# drops naughty clients
WS_MAX_INBOUND_MSGS = 50
WS_MAX_MSG_SIZE = 4096

COINBASE_WS = "wss://ws-feed.exchange.coinbase.com"
COINBASE_SUBSCRIBE = {
    "type": "subscribe",
    "channels": [{"name": "matches", "product_ids": ["BTC-USD"]}],
}

GAMMA_API = "https://gamma-api.polymarket.com"
CLOB_API = "https://clob.polymarket.com"
POLY_WS = "wss://ws-subscriptions-clob.polymarket.com/ws/market"

EPOCH_INTERVAL = 300  # Polymarket BTC up/down markets roll every 5 minutes
RECONNECT_DELAYS = [1, 2, 4, 8, 16]
HEARTBEAT_INTERVAL_S = 60


# websocket relay

class WsRelay:
    """Serves index.html and broadcasts JSON rows to connected browsers."""

    def __init__(
        self,
        middleware=None,
        max_ws_clients: int = DEFAULT_MAX_WS_CLIENTS,
        max_ws_per_ip: int = DEFAULT_MAX_WS_PER_IP,
        trust_proxy: bool = False,
    ) -> None:
        self._clients: set[web.WebSocketResponse] = set()
        self._clients_per_ip: Counter[str] = Counter()
        self._runner: web.AppRunner | None = None
        self._middleware = middleware
        self._max_ws_clients = max_ws_clients
        self._max_ws_per_ip = max_ws_per_ip
        self._trust_proxy = trust_proxy

    async def handle_ws(self, request: web.Request) -> web.StreamResponse:
        ip = client_ip(request, self._trust_proxy)

        if len(self._clients) >= self._max_ws_clients:
            logger.warning("WS refused for %s: server at %d-client cap", ip, self._max_ws_clients)
            return web.Response(status=503, text="Too many connections")
        if self._clients_per_ip[ip] >= self._max_ws_per_ip:
            logger.warning("WS refused for %s: per-IP cap (%d) reached", ip, self._max_ws_per_ip)
            return web.Response(status=429, text="Too many connections from this address")

        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=WS_MAX_MSG_SIZE)
        await ws.prepare(request)
        self._clients.add(ws)
        self._clients_per_ip[ip] += 1
        logger.info("Browser client connected from %s (%d total)", ip, len(self._clients))
        try:
            inbound = 0
            async for _ in ws:
                inbound += 1
                if inbound > WS_MAX_INBOUND_MSGS:
                    logger.warning("Dropping chatty WS client %s (>%d inbound msgs)", ip, WS_MAX_INBOUND_MSGS)
                    break
        finally:
            self._clients.discard(ws)
            self._clients_per_ip[ip] -= 1
            if self._clients_per_ip[ip] <= 0:
                del self._clients_per_ip[ip]
            logger.info("Browser client disconnected (%d remaining)", len(self._clients))
        return ws

    async def broadcast(self, row: dict[str, Any]) -> None:
        if not self._clients:
            return
        payload = json.dumps(row)
        stale: list[web.WebSocketResponse] = []
        for ws in self._clients:
            try:
                await ws.send_str(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self._clients.discard(ws)

    @staticmethod
    async def _serve_index(request: web.Request) -> web.Response:
        index_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
        with open(index_path, "rb") as f:
            content = f.read()
        return web.Response(body=content, content_type="text/html")

    async def start(self, host: str, port: int, ssl_context: ssl.SSLContext | None) -> None:
        middlewares = [self._middleware] if self._middleware else []
        # client_max_size: nothing legitimate POSTs anything here
        app = web.Application(middlewares=middlewares, client_max_size=4096)
        app.router.add_get("/ws", self.handle_ws)
        app.router.add_get("/", self._serve_index)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, host, port, ssl_context=ssl_context)
        await site.start()
        scheme = "https" if ssl_context else "http"
        ws_scheme = "wss" if ssl_context else "ws"
        logger.info("Relay on %s://%s:%d | %s://%s:%d/ws", scheme, host, port, ws_scheme, host, port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()


# coinbase BTC-USD feed

async def run_coinbase_feed(relay: WsRelay, stop_event: asyncio.Event) -> None:
    """Stream BTC-USD matches from Coinbase, broadcast each as a tick row."""
    retry_count = 0
    while not stop_event.is_set():
        connected_at = None
        try:
            connected_at = time.time()
            async with websockets.connect(COINBASE_WS, ping_interval=20) as ws:
                await ws.send(json.dumps(COINBASE_SUBSCRIBE))
                logger.info("Coinbase WS connected — subscribed to BTC-USD matches")
                last_heartbeat = time.time()
                trade_count = 0

                async for raw in ws:
                    if stop_event.is_set():
                        return
                    msg = json.loads(raw)
                    if msg.get("type") != "match":
                        continue

                    now = time.time()
                    trade_count += 1
                    if now - last_heartbeat >= HEARTBEAT_INTERVAL_S:
                        logger.info("Coinbase heartbeat | trades=%d", trade_count)
                        last_heartbeat = now
                        trade_count = 0

                    try:
                        dt = datetime.fromisoformat(msg.get("time", "").replace("Z", "+00:00"))
                        timestamp_ms = int(dt.timestamp() * 1000)
                    except Exception:
                        timestamp_ms = int(now * 1000)

                    await relay.broadcast({
                        "timestamp_ms": timestamp_ms,
                        "price": float(msg["price"]),
                        "feed_type": "match",
                    })
        except asyncio.CancelledError:
            return
        except Exception as exc:
            if stop_event.is_set():
                return
            if connected_at and time.time() - connected_at > 60:
                retry_count = 0
            delay = RECONNECT_DELAYS[min(retry_count, len(RECONNECT_DELAYS) - 1)]
            logger.warning("Coinbase feed error (reconnecting in %ds): %s", delay, exc)
            retry_count += 1
            await asyncio.sleep(delay)


# Polymarket 5-min BTC up/down feed

def _current_epoch() -> int:
    return (int(time.time()) // EPOCH_INTERVAL) * EPOCH_INTERVAL


async def _resolve_market(session: aiohttp.ClientSession, epoch: int) -> dict[str, Any] | None:
    """slug -> Gamma event -> conditionId -> CLOB market -> Up/Down token IDs."""
    slug = f"btc-updown-5m-{epoch}"
    try:
        async with session.get(
            f"{GAMMA_API}/events", params={"slug": slug},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                logger.warning("Gamma /events slug=%s returned %d", slug, resp.status)
                return None
            events = await resp.json()
    except Exception as exc:
        logger.warning("Gamma lookup error for %s: %s", slug, exc)
        return None

    if not events:
        return None
    markets = events[0].get("markets") or []
    if not markets:
        return None
    condition_id = markets[0].get("conditionId", "")
    if not condition_id:
        return None

    try:
        async with session.get(
            f"{CLOB_API}/markets/{condition_id}",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                return None
            clob_market = await resp.json()
    except Exception as exc:
        logger.warning("CLOB market lookup error: %s", exc)
        return None

    tokens: dict[str, str] = {}
    for t in clob_market.get("tokens") or []:
        outcome = (t.get("outcome") or "").upper()
        token_id = t.get("token_id", "")
        if not token_id:
            continue
        if "UP" in outcome:
            tokens["Up"] = token_id
        elif "DOWN" in outcome:
            tokens["Down"] = token_id

    if not tokens:
        return None
    logger.info("Resolved market slug=%s tokens=%d", slug, len(tokens))
    return {"slug": slug, "condition_id": condition_id, "tokens": tokens}


@dataclass
class ContractState:
    contract: str = ""  # "Up" or "Down"
    best_bid: float = 0.0
    best_ask: float = 0.0


async def _broadcast_book(relay: WsRelay, state: ContractState) -> None:
    """Emit the two message shapes the frontend chart consumes."""
    ts = int(time.time() * 1000)
    await relay.broadcast({
        "type": "poly_bid",
        "timestamp_ms": ts,
        "contract": state.contract,
        "best_bid": state.best_bid,
    })
    await relay.broadcast({
        "type": "poly_ask",
        "timestamp_ms": ts,
        "contract": state.contract,
        "best_ask": state.best_ask,
    })


async def _run_poly_ws(
    relay: WsRelay,
    stop_event: asyncio.Event,
    http_session: aiohttp.ClientSession,
) -> None:
    """One Polymarket WS connection lifetime: subscribe, dispatch, roll epochs."""
    current_market: dict[str, Any] | None = None
    current_epoch = 0
    states: dict[str, ContractState] = {}  # token_id -> state

    async with http_session.ws_connect(POLY_WS, heartbeat=30) as ws:
        logger.info("Polymarket WS connected")

        async def subscribe(market: dict[str, Any], *, initial: bool = False) -> None:
            asset_ids = []
            for contract_name, token_id in market["tokens"].items():
                asset_ids.append(token_id)
                states[token_id] = ContractState(contract=contract_name)
            if initial:
                sub_msg = {
                    "assets_ids": asset_ids,
                    "type": "market",
                    "initial_dump": True,
                    "level": 2,
                    "custom_feature_enabled": True,
                }
            else:
                sub_msg = {
                    "operation": "subscribe",
                    "assets_ids": asset_ids,
                    "level": 2,
                    "custom_feature_enabled": True,
                }
            await ws.send_json(sub_msg)
            logger.info("Subscribed to %d tokens for epoch %d", len(asset_ids), current_epoch)

        async def unsubscribe(market: dict[str, Any]) -> None:
            asset_ids = list(market["tokens"].values())
            await ws.send_json({"operation": "unsubscribe", "assets_ids": asset_ids})
            for tid in asset_ids:
                states.pop(tid, None)

        current_epoch = _current_epoch()
        while not stop_event.is_set():
            current_market = await _resolve_market(http_session, current_epoch)
            if current_market is not None:
                break
            new_epoch = _current_epoch()
            if new_epoch != current_epoch:
                current_epoch = new_epoch
            else:
                await asyncio.sleep(1.0)

        if stop_event.is_set() or current_market is None:
            return
        await subscribe(current_market, initial=True)

        async def ping_loop() -> None:
            while not stop_event.is_set():
                try:
                    await ws.send_str("PING")
                except Exception:
                    return
                await asyncio.sleep(10)

        async def epoch_checker() -> None:
            nonlocal current_epoch, current_market
            while not stop_event.is_set():
                await asyncio.sleep(1.0)
                epoch = _current_epoch()
                if epoch == current_epoch:
                    continue
                logger.info("Epoch transition: %d -> %d", current_epoch, epoch)
                current_epoch = epoch
                new_market = None
                while not stop_event.is_set() and _current_epoch() == epoch:
                    new_market = await _resolve_market(http_session, epoch)
                    if new_market is not None:
                        break
                    await asyncio.sleep(1.0)
                if new_market is None or stop_event.is_set():
                    continue
                if current_market is not None:
                    await unsubscribe(current_market)
                current_market = new_market
                await subscribe(current_market)

        ping_task = asyncio.create_task(ping_loop())
        epoch_task = asyncio.create_task(epoch_checker())
        try:
            async for msg in ws:
                if stop_event.is_set():
                    break
                if msg.type == aiohttp.WSMsgType.TEXT:
                    if msg.data == "PONG":
                        continue
                    try:
                        data = json.loads(msg.data)
                    except json.JSONDecodeError:
                        continue
                    events = data if isinstance(data, list) else [data]
                    for event in events:
                        await _handle_poly_event(event, states, relay)
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    logger.warning("Polymarket WS closed/error: %s", msg.data)
                    break
        finally:
            ping_task.cancel()
            epoch_task.cancel()
            await asyncio.gather(ping_task, epoch_task, return_exceptions=True)


async def _handle_poly_event(
    event: dict[str, Any],
    states: dict[str, ContractState],
    relay: WsRelay,
) -> None:
    event_type = event.get("event_type", "")
    state = states.get(event.get("asset_id", ""))
    if state is None:
        return

    if event_type == "book":
        bids = sorted(event.get("bids") or [], key=lambda b: -float(b["price"]))
        asks = sorted(event.get("asks") or [], key=lambda a: float(a["price"]))
        state.best_bid = float(bids[0]["price"]) if bids else 0.0
        state.best_ask = float(asks[0]["price"]) if asks else 0.0
        await _broadcast_book(relay, state)

    elif event_type == "best_bid_ask":
        bb = event.get("best_bid")
        ba = event.get("best_ask")
        if bb is not None:
            state.best_bid = float(bb)
        if ba is not None:
            state.best_ask = float(ba)
        await _broadcast_book(relay, state)

    # price_change is followed by best_bid_ask


async def run_polymarket_feed(relay: WsRelay, stop_event: asyncio.Event) -> None:
    """Connect to Polymarket WS with reconnect logic."""
    retry_count = 0
    async with aiohttp.ClientSession() as http_session:
        while not stop_event.is_set():
            connected_at = None
            try:
                connected_at = time.time()
                await _run_poly_ws(relay, stop_event, http_session)
                if not stop_event.is_set():
                    logger.warning("Polymarket WS closed cleanly, reconnecting in 2s...")
                    await asyncio.sleep(2.0)
            except asyncio.CancelledError:
                return
            except Exception as exc:
                if stop_event.is_set():
                    return
                if connected_at and time.time() - connected_at > 60:
                    retry_count = 0
                delay = RECONNECT_DELAYS[min(retry_count, len(RECONNECT_DELAYS) - 1)]
                logger.warning("Polymarket feed error (reconnecting in %ds): %s", delay, exc)
                retry_count += 1
                await asyncio.sleep(delay)


# main

def _build_security() -> tuple[Any, ssl.SSLContext | None, bool]:
    """Read env vars, return (middleware, ssl_context, trust_proxy)."""
    trust_proxy = os.environ.get("TRUST_PROXY", "") == "1"

    # tls
    ssl_ctx: ssl.SSLContext | None = None
    cert_file = os.environ.get("TLS_CERT", "")
    key_file = os.environ.get("TLS_KEY", "")
    if cert_file or key_file:
        if not (cert_file and key_file):
            logger.error("Both TLS_CERT and TLS_KEY must be set (got only one)")
            sys.exit(1)
        try:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(cert_file, key_file)
        except (FileNotFoundError, ssl.SSLError) as exc:
            logger.error("TLS setup failed: %s\nRun: python gen_cert.py --ip <public-ip>", exc)
            sys.exit(1)
        logger.info("TLS enabled (cert=%s)", cert_file)

    # auth, could toggle
    authenticator = None
    password_hash = os.environ.get("AUTH_PASSWORD_HASH", "")
    if password_hash:
        username = os.environ.get("AUTH_USERNAME", "admin")
        authenticator = Authenticator(username, password_hash)
        logger.info("Basic Auth enabled (username=%s)", username)
        if ssl_ctx is None:
            logger.warning(
                "Auth is enabled WITHOUT TLS — credentials and session cookies "
                "travel in cleartext. Fine behind an HTTPS reverse proxy or SSH "
                "tunnel; do not expose this directly to the internet."
            )
    else:
        logger.warning("Auth disabled — relay is open (set AUTH_PASSWORD_HASH to enable)")

    ttl_hours = int(os.environ.get("SESSION_TTL_HOURS", "24"))
    sessions = SessionStore(ttl_s=ttl_hours * 3600)
    # tls termination at a reverse proxy also warrants secure cookies ig
    secure_cookies = ssl_ctx is not None or trust_proxy
    middleware = make_security_middleware(authenticator, sessions, secure_cookies, trust_proxy)
    return middleware, ssl_ctx, trust_proxy


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    max_ws_clients = int(os.environ.get("MAX_WS_CLIENTS", DEFAULT_MAX_WS_CLIENTS))
    max_ws_per_ip = int(os.environ.get("MAX_WS_PER_IP", DEFAULT_MAX_WS_PER_IP))

    middleware, ssl_ctx, trust_proxy = _build_security()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            signal.signal(sig, lambda *_: stop_event.set())

    relay = WsRelay(
        middleware=middleware,
        max_ws_clients=max_ws_clients,
        max_ws_per_ip=max_ws_per_ip,
        trust_proxy=trust_proxy,
    )
    await relay.start(host, port, ssl_ctx)

    tasks = [
        asyncio.create_task(run_coinbase_feed(relay, stop_event), name="coinbase_feed"),
        asyncio.create_task(run_polymarket_feed(relay, stop_event), name="poly_feed"),
    ]
    try:
        await stop_event.wait()
    finally:
        stop_event.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await relay.stop()
        logger.info("Stopped cleanly")


if __name__ == "__main__":
    asyncio.run(main())
