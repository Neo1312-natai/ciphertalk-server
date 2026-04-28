"""
CipherTalk Relay Server — Stateless Encrypted Relay via WebSockets
===================================================================

Uniwersalny serwer relay dla platformy Render (i każdej innej obsługującej
Python 3.10+).

ROLA SERWERA:
 • Bezstanowy przekaźnik pakietów JSON między klientami w tym samym pokoju.
 • Serwer NIE posiada kluczy deszyfrujących — widzi wyłącznie zaszyfrowany
   ciphertext (AES-256-GCM), room_id i nazwę nadawcy.
 • Zero logowania treści (tylko metadane połączenia).

PROTOKÓŁ (identyczny dla iOS i PC):
  → { "action": "join",    "room_id": "...", "sender": "Alice" }
  → { "action": "leave",   "room_id": "...", "sender": "Alice" }
  → { "action": "message", "room_id": "...", "sender": "Alice",
      "payload": { "type": "text"|"file", "ciphertext": "...", "nonce": "...",
                   "meta": {...} } }
  ← { "action": "joined",  "room_id": "...", "sender": "Bob",   "peers": [...] }
  ← { "action": "left",    "room_id": "...", "sender": "Bob",   "peers": [...] }
  ← { "action": "message", "room_id": "...", "sender": "Alice", "payload": {...} }
  ← { "action": "error",   "reason": "..." }

URUCHOMIENIE LOKALNIE:
    pip install websockets
    python relay_server.py

URUCHOMIENIE NA RENDER.COM:
    Start Command:  python relay_server.py
    Plan:           Free / Starter (wystarczy 512 MB RAM)
    Env var:        PORT (ustawiana automatycznie przez Render)

Serwer nasłuchuje na 0.0.0.0:$PORT (domyślnie 8765).
Klient łączy się przez:  wss://<nazwa-serwisu>.onrender.com
"""

import os
import json
import time
import asyncio
import logging
from collections import deque

import websockets
from websockets.exceptions import ConnectionClosed


# =============================================================================
# KONFIGURACJA
# =============================================================================
HOST                 = "0.0.0.0"
PORT                 = int(os.environ.get("PORT", 8765))
MAX_MESSAGE_SIZE     = 12 * 1024 * 1024    # 12 MB — zaszyfrowana paczka
PING_INTERVAL        = 20                   # sekundy — keepalive
PING_TIMEOUT         = 20                   # sekundy — timeout pong
MAX_PEERS_PER_ROOM   = 8                    # anti-DoS: max klientów w pokoju
MAX_ROOM_ID_LEN      = 64
MAX_SENDER_LEN       = 32

# Rate limiting per-connection (anti-flood)
RATE_LIMIT_WINDOW_S  = 10                   # okno
RATE_LIMIT_MAX_MSGS  = 200                  # max 200 akcji / 10s = 20/s
RATE_LIMIT_MAX_ERRS  = 20                   # po 20 błędach - kick

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("relay")


# =============================================================================
# STAN SERWERA (in-memory, ulotny — brak persystencji)
# =============================================================================
# room_id  ->  { websocket: sender_name }
# UWAGA: zwykły dict, NIE defaultdict — defaultdict tworzy pusty wpis przy
# samym sprawdzeniu `rooms[room_id]`, co było wektorem memory leak.
rooms: dict[str, dict] = {}
rooms_lock = asyncio.Lock()


# =============================================================================
# POMOCNICZE
# =============================================================================
async def send_json(ws, obj):
    """Wysyła JSON do klienta, ignoruje błędy (klient mógł się rozłączyć)."""
    try:
        await ws.send(json.dumps(obj, ensure_ascii=False))
    except (ConnectionClosed, RuntimeError):
        pass


async def broadcast_room(room_id: str, obj: dict, exclude=None):
    """Rozsyła obj do wszystkich klientów w pokoju oprócz `exclude`."""
    async with rooms_lock:
        targets = [ws for ws in rooms.get(room_id, {}) if ws is not exclude]
    for ws in targets:
        await send_json(ws, obj)


def peers_of(room_id: str) -> list[str]:
    """Lista nicków w pokoju (do informowania klientów)."""
    return list(rooms.get(room_id, {}).values())


def _cleanup_empty_room_locked(room_id: str):
    """Usuwa pusty pokój z `rooms`. Wywołuj TYLKO z wnętrza rooms_lock."""
    if room_id in rooms and not rooms[room_id]:
        del rooms[room_id]


# Dozwolone znaki w room_id i sender — blokuje injection do logów, \r\n,
# znaki kontrolne, nazwy ścieżek.
_SAFE_ID_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
)


def validate_str(value, max_len: int, field: str) -> str | None:
    """Zwraca poprawny string lub None. Brak wyjątków do klienta.

    Odrzuca: nie-string, pusty, za długi, znaki kontrolne, znaki spoza
    białej listy (anty-injection w logach i w nazwach).
    """
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > max_len:
        return None
    if not all(c in _SAFE_ID_CHARS for c in v):
        return None
    return v


def validate_message_payload(payload) -> bool:
    """Sprawdza kształt paczki `message` — relay nie deszyfruje, ale
    odfiltrowuje oczywisty bełkot, żeby klient nie musiał się tym zajmować.
    """
    if not isinstance(payload, dict):
        return False
    t = payload.get("type")
    if t not in ("text", "file", "announce"):
        return False
    if not isinstance(payload.get("nonce"), str):
        return False
    if not isinstance(payload.get("ciphertext"), str):
        return False
    # Podpis Ed25519: 64 bajty → 88 znaków base64. Klucz publiczny: 32B → 64 hex.
    sig = payload.get("sig")
    if not isinstance(sig, str) or not (1 <= len(sig) <= 128):
        return False
    pub = payload.get("sender_pub")
    if not isinstance(pub, str) or len(pub) != 64:
        return False
    # Rozmiary
    if len(payload["ciphertext"]) > MAX_MESSAGE_SIZE:
        return False
    if len(payload["nonce"]) > 64:
        return False
    if t == "file":
        meta = payload.get("meta")
        if not isinstance(meta, dict):
            return False
        fn = meta.get("filename")
        if not isinstance(fn, str) or len(fn) > 255:
            return False
    return True


# =============================================================================
# OBSŁUGA POJEDYNCZEGO KLIENTA
# =============================================================================
async def handle_client(ws):
    peer_addr = ws.remote_address
    current_room: str | None = None
    current_sender: str | None = None
    # Rate limiting per-połączenie
    recent_times = deque(maxlen=RATE_LIMIT_MAX_MSGS + 1)
    error_count = 0
    log.info("Connected: %s", peer_addr)

    async def send_error(reason: str):
        nonlocal error_count
        error_count += 1
        await send_json(ws, {"action": "error", "reason": reason})

    try:
        async for raw in ws:
            # --- Rate limiting --------------------------------------------
            now = time.monotonic()
            recent_times.append(now)
            if len(recent_times) > RATE_LIMIT_MAX_MSGS:
                window_start = recent_times[0]
                if now - window_start < RATE_LIMIT_WINDOW_S:
                    # Spam wykryty - rozłącz bez dalszych ceregieli.
                    log.warning("Rate limit exceeded, kicking %s", peer_addr)
                    await send_json(ws, {"action": "error", "reason": "rate_limited"})
                    break

            if error_count >= RATE_LIMIT_MAX_ERRS:
                log.warning("Kick %s: too many errors", peer_addr)
                break

            # --- Parsing + walidacja ---------------------------------------
            if isinstance(raw, bytes):
                # Relay obsługuje tylko tekstowe ramki JSON.
                await send_error("binary_frames_not_supported")
                continue

            if len(raw) > MAX_MESSAGE_SIZE:
                # Zwykle zatrzyma to już websockets (max_size), ale na wszelki
                # wypadek dodatkowa bariera.
                await send_error("message_too_large")
                continue

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await send_error("invalid_json")
                continue

            if not isinstance(msg, dict):
                await send_error("invalid_shape")
                continue

            action = msg.get("action")
            room_id = validate_str(msg.get("room_id"), MAX_ROOM_ID_LEN, "room_id")
            sender = validate_str(msg.get("sender"), MAX_SENDER_LEN, "sender")

            if action not in ("join", "leave", "message"):
                await send_error("unknown_action")
                continue
            if not room_id or not sender:
                await send_error("invalid_fields")
                continue

            # --- JOIN ------------------------------------------------------
            if action == "join":
                async with rooms_lock:
                    room = rooms.get(room_id)
                    if room is None:
                        room = {}
                        rooms[room_id] = room
                    # Sprawdź limit BEZ tworzenia nowego wpisu (już utworzony wyżej świadomie)
                    if len(room) >= MAX_PEERS_PER_ROOM and ws not in room:
                        # Jeśli właśnie stworzyliśmy pusty pokój tylko dla sprawdzenia,
                        # a nie może dołączyć - rollback.
                        if not room:
                            del rooms[room_id]
                        await send_error("room_full")
                        continue

                    # Jeśli klient zmienia pokój — wyjdź ze starego.
                    old_room_id = None
                    old_peers = None
                    if current_room and current_room != room_id:
                        old_room = rooms.get(current_room, {})
                        old_room.pop(ws, None)
                        old_peers = list(old_room.values())
                        if not old_room:
                            rooms.pop(current_room, None)
                        old_room_id = current_room

                    room[ws] = sender
                    peers_now = list(room.values())

                if old_room_id:
                    await broadcast_room(old_room_id, {
                        "action": "left",
                        "room_id": old_room_id,
                        "sender": current_sender or sender,
                        "peers": old_peers or [],
                    })

                current_room = room_id
                current_sender = sender

                # Powiadom nowego i resztę pokoju.
                await send_json(ws, {
                    "action": "joined",
                    "room_id": room_id,
                    "sender": sender,
                    "peers": peers_now,
                    "self": True,
                })
                await broadcast_room(room_id, {
                    "action": "joined",
                    "room_id": room_id,
                    "sender": sender,
                    "peers": peers_now,
                }, exclude=ws)

                log.info("JOIN  room=%s sender=%s peers=%d",
                         room_id, sender, len(peers_now))
                continue

            # --- LEAVE -----------------------------------------------------
            if action == "leave":
                # Sender w ogłoszeniu LEAVE bierzemy z zapamiętanej sesji,
                # nie z pola w wiadomości — anti-spoofing.
                leave_sender = current_sender or sender
                async with rooms_lock:
                    room = rooms.get(room_id)
                    if room is not None:
                        room.pop(ws, None)
                        peers_now = list(room.values())
                        if not room:
                            del rooms[room_id]
                    else:
                        peers_now = []

                await broadcast_room(room_id, {
                    "action": "left",
                    "room_id": room_id,
                    "sender": leave_sender,
                    "peers": peers_now,
                })
                if current_room == room_id:
                    current_room = None
                    current_sender = None
                log.info("LEAVE room=%s sender=%s peers=%d",
                         room_id, leave_sender, len(peers_now))
                continue

            # --- MESSAGE (relay) ------------------------------------------
            if action == "message":
                payload = msg.get("payload")
                if not validate_message_payload(payload):
                    await send_error("invalid_payload")
                    continue
                # Klient musi być w tym pokoju, do którego wysyła.
                # Blokuje to wstrzykiwanie cross-room przez pojedynczego zalogowanego klienta.
                if current_room != room_id:
                    await send_error("not_in_room")
                    continue

                # Przekazujemy JAK JEST — serwer nie zna kluczy.
                await broadcast_room(room_id, {
                    "action": "message",
                    "room_id": room_id,
                    "sender": sender,
                    "payload": payload,
                }, exclude=ws)

    except ConnectionClosed:
        pass
    except Exception as e:
        log.exception("Handler error: %s", e)
    finally:
        # Sprzątanie po rozłączeniu.
        if current_room:
            async with rooms_lock:
                rooms.get(current_room, {}).pop(ws, None)
                peers_now = peers_of(current_room)
                if not rooms.get(current_room):
                    rooms.pop(current_room, None)
            await broadcast_room(current_room, {
                "action": "left",
                "room_id": current_room,
                "sender": current_sender or "?",
                "peers": peers_now,
            })
        log.info("Disconnected: %s", peer_addr)


# =============================================================================
# START
# =============================================================================
async def main():
    log.info("CipherTalk Relay starting on %s:%d", HOST, PORT)
    async with websockets.serve(
        handle_client,
        HOST,
        PORT,
        max_size=MAX_MESSAGE_SIZE,
        ping_interval=PING_INTERVAL,
        ping_timeout=PING_TIMEOUT,
    ):
        log.info("Relay ready. Waiting for clients...")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Relay shutting down.")
