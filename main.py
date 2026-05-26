import asyncio
import hashlib
import json
import math
import os
import secrets as secrets_mod
import time
from collections import deque
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from database import (
    init_db, get_chats, get_messages, get_chat, get_message_count,
    delete_message, save_sent_message,
)
from bot import setup_bot_with_handlers

load_dotenv()

BASE_DIR = Path(__file__).parent
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8888"))
FLIPPER_SECRET = os.getenv("FLIPPER_SECRET", "")
_FLIPPER_KEY   = hashlib.sha256(FLIPPER_SECRET.encode()).digest() if FLIPPER_SECRET else b""
_FLIPPER_HASH  = hashlib.sha256(FLIPPER_SECRET.encode()).hexdigest() if FLIPPER_SECRET else ""

app = FastAPI(title="Flipper Telegram")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
basic_auth = HTTPBasic()

AVATAR_COLORS = [
    "#e17055", "#6c5ce7", "#00b894", "#0984e3", "#fdcb6e",
    "#e84393", "#00cec9", "#b2bec3", "#fd79a8", "#55efc4",
]


def coloridx(name: str) -> str:
    return AVATAR_COLORS[ord(name[0].lower()) % len(AVATAR_COLORS)] if name else AVATAR_COLORS[0]


def fmtdate(s: str) -> str:
    return s[:16].replace("T", " ") if s else ""


templates.env.filters["coloridx"] = coloridx
templates.env.filters["fmtdate"] = fmtdate


# ── Auth ─────────────────────────────────────────────────────────────────────

FAIL_WINDOW_SEC = 60
FAIL_MAX = 3
_fail_log: dict[str, deque] = {}


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _check_rate_limit(ip: str):
    now = time.time()
    log = _fail_log.get(ip)
    if not log:
        return
    while log and now - log[0] > FAIL_WINDOW_SEC:
        log.popleft()
    if not log:
        _fail_log.pop(ip, None)
        return
    if len(log) >= FAIL_MAX:
        retry = int(FAIL_WINDOW_SEC - (now - log[0])) + 1
        raise HTTPException(
            status_code=429,
            headers={"Retry-After": str(retry)},
            detail="Too many failed attempts",
        )


def _record_failure(ip: str):
    _fail_log.setdefault(ip, deque()).append(time.time())


def require_web_auth(request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth)):
    ip = _client_ip(request)
    _check_rate_limit(ip)
    ok = secrets_mod.compare_digest(
        credentials.password.encode(), FLIPPER_SECRET.encode()
    )
    if not ok:
        _record_failure(ip)
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Flipper Telegram"'},
            detail="Unauthorized",
        )


async def require_secret(request: Request):
    ip = _client_ip(request)
    _check_rate_limit(ip)
    if request.headers.get("X-Secret") != _FLIPPER_HASH:
        _record_failure(ip)
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── Web UI ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_web_auth)])
async def index(request: Request):
    chats = await get_chats()
    return templates.TemplateResponse(request, "index.html", {"chats": chats})


@app.get("/chat/{chat_id}", response_class=HTMLResponse, dependencies=[Depends(require_web_auth)])
async def chat_view(request: Request, chat_id: int, page: int = 0):
    chat = await get_chat(chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    per_page = 30
    messages = await get_messages(chat_id, page=page, per_page=per_page)
    count = await get_message_count(chat_id)
    total_pages = max(1, math.ceil(count / per_page))
    return templates.TemplateResponse(request, "chat.html", {
        "chat": chat,
        "messages": messages,
        "page": page,
        "total_pages": total_pages,
        "has_prev": page > 0,
        "has_next": page < total_pages - 1,
    })


# ── JSON API ──────────────────────────────────────────────────────────────────

@app.get("/api/chats", dependencies=[Depends(require_web_auth)])
async def api_chats():
    return await get_chats()


@app.get("/api/chats/{chat_id}/messages", dependencies=[Depends(require_web_auth)])
async def api_messages(chat_id: int, page: int = 0, per_page: int = 20):
    msgs = await get_messages(chat_id, page=page, per_page=per_page)
    count = await get_message_count(chat_id)
    return {"messages": msgs, "total": count, "page": page,
            "pages": math.ceil(count / per_page)}


@app.delete("/api/messages/{message_id}", dependencies=[Depends(require_web_auth)])
async def api_delete_message(message_id: int):
    deleted = await delete_message(message_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Message not found")
    return {"ok": True}


# ── Flipper crypto ────────────────────────────────────────────────────────────

def _req_key(request: Request) -> bytes:
    nonce_hex = request.headers.get("X-Nonce", "")
    if nonce_hex:
        try:
            return hashlib.sha256(_FLIPPER_KEY + bytes.fromhex(nonce_hex)).digest()
        except ValueError:
            pass
    return _FLIPPER_KEY

def _xor_crypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i & 31] for i, b in enumerate(data))

def _xor_encrypt(data: bytes, key: bytes) -> str:
    return _xor_crypt(data, key).hex()

def _xor_decrypt(hex_str: str, key: bytes) -> bytes:
    return _xor_crypt(bytes.fromhex(hex_str.strip()), key)

def _flipper_resp(data, key: bytes) -> Response:
    return Response(
        content=_xor_encrypt(json.dumps(data, separators=(",", ":")).encode(), key),
        media_type="text/plain",
    )


# ── Flipper API ───────────────────────────────────────────────────────────────

_CYR_MAP = {
    "А": "A", "Б": "B", "В": "V", "Г": "G", "Д": "D", "Е": "E", "Ё": "E",
    "Ж": "Zh", "З": "Z", "И": "I", "Й": "J", "К": "K", "Л": "L", "М": "M",
    "Н": "N", "О": "O", "П": "P", "Р": "R", "С": "S", "Т": "T", "У": "U",
    "Ф": "F", "Х": "H", "Ц": "Ts", "Ч": "Ch", "Ш": "Sh", "Щ": "Sch",
    "Ъ": "", "Ы": "Y", "Ь": "", "Э": "E", "Ю": "Yu", "Я": "Ya",
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "j", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def _asc(s: str, maxlen: int) -> str:
    out = []
    skip_next = False
    for ch in (s or ""):
        cp = ord(ch)
        if 32 <= cp < 127:
            out.append(ch)
            skip_next = False
        elif ch in _CYR_MAP:
            out.append(_CYR_MAP[ch])
            skip_next = False
        elif cp == 0x200D:  # ZWJ — next codepoint completes the same emoji
            skip_next = True
        elif 0xFE00 <= cp <= 0xFE0F:  # variation selectors
            pass
        elif 0x1F3FB <= cp <= 0x1F3FF:  # skin-tone modifiers
            pass
        elif cp > 127:
            if not skip_next:
                out.append("[]")
            skip_next = False
    clean = "".join(out).strip()
    return (clean or "?")[:maxlen]


@app.get("/flipper/ping", dependencies=[Depends(require_secret)])
async def flipper_ping(request: Request):
    return _flipper_resp({"ok": 1}, _req_key(request))


@app.get("/flipper/chats", dependencies=[Depends(require_secret)])
async def flipper_chats(request: Request):
    key = _req_key(request)
    chats = await get_chats(limit=20)
    return _flipper_resp({
        "items": [
            {"id": c["id"], "name": _asc(c["name"], 18), "n": c["message_count"]}
            for c in chats
        ]
    }, key)


@app.get("/flipper/messages/{chat_id}", dependencies=[Depends(require_secret)])
async def flipper_messages(request: Request, chat_id: int, page: int = 0):
    key = _req_key(request)
    per_page = 5
    count = await get_message_count(chat_id)
    total_pages = max(1, math.ceil(count / per_page))
    page = max(0, min(page, total_pages - 1))
    msgs = await get_messages(chat_id, page=page, per_page=per_page, newest_first=True)
    return _flipper_resp({
        "page": page,
        "pages": total_pages,
        "msgs": [
            {
                "f": _asc(m["from_name"] or "?", 12),
                "t": _asc(m["text"] or "", 256),
                "d": m["date"][11:16] if m["date"] and len(m["date"]) > 16 else "",
            }
            for m in msgs
        ],
    }, key)


_bot_app = None


@app.post("/flipper/send/{chat_id}", dependencies=[Depends(require_secret)])
async def flipper_send(chat_id: int, request: Request):
    key = _req_key(request)
    try:
        body = json.loads(_xor_decrypt((await request.body()).decode(), key))
    except Exception:
        return _flipper_resp({"ok": 0, "error": "decrypt"}, key)
    text = (body.get("text") or "").strip()
    if not text:
        return _flipper_resp({"ok": 0, "error": "empty"}, key)
    if _bot_app is None:
        return _flipper_resp({"ok": 0, "error": "bot not ready"}, key)
    try:
        msg = await _bot_app.bot.send_message(chat_id=chat_id, text=text)
        await save_sent_message(chat_id, text, telegram_id=msg.message_id)
    except Exception as e:
        return _flipper_resp({"ok": 0, "error": str(e)[:50]}, key)
    return _flipper_resp({"ok": 1}, key)


# ── Runner ────────────────────────────────────────────────────────────────────

async def run_bot():
    global _bot_app
    _bot_app = setup_bot_with_handlers()
    async with _bot_app:
        await _bot_app.start()
        await _bot_app.updater.start_polling(drop_pending_updates=True)
        await asyncio.Future()


async def main():
    if not FLIPPER_SECRET:
        raise SystemExit("FLIPPER_SECRET is not set — configure it in .env before starting")
    await init_db()
    ssl_key = BASE_DIR / "key.pem"
    ssl_cert = BASE_DIR / "cert.pem"
    if not ssl_key.exists() or not ssl_cert.exists():
        print("WARNING: cert.pem / key.pem not found — running over plain HTTP (run gen_cert.sh)")
    config = uvicorn.Config(
        app,
        host=HOST,
        port=PORT,
        log_level="info",
        ssl_keyfile=str(ssl_key) if ssl_key.exists() else None,
        ssl_certfile=str(ssl_cert) if ssl_cert.exists() else None,
    )
    server = uvicorn.Server(config)
    await asyncio.gather(server.serve(), run_bot())


if __name__ == "__main__":
    asyncio.run(main())
