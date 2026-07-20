import os
import json
import time
import asyncio
import uuid
import secrets
import threading
import httpx
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from collections import defaultdict

from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = os.environ.get("MONGO_URI", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "zyper-admin-2026")
REAL_BASE = "https://license.zyper.app"

db = None
client = None
_cache = {}
_cache_lock = threading.Lock()

ENDPOINTS = {
    "/v1/social-modules": "GET",
    "/v1/modules": "GET",
    "/v1/checker-modules": "GET",
}

kill_switch = False

# Rate limiting
_rate_limit = defaultdict(list)
_ip_cache = {}
_geo_lock = threading.Lock()
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_BLOCK = 300

def _check_rate_limit(ip):
    now = time.time()
    if ip in _blocked_ips:
        if now < _blocked_ips[ip]:
            return False
        del _blocked_ips[ip]
    if ip in _rate_limit:
        attempts = _rate_limit[ip]
        attempts[:] = [t for t in attempts if now - t < RATE_LIMIT_BLOCK]
        if len(attempts) >= RATE_LIMIT_MAX:
            _mark_blocked(ip)
            return False
    return True

def _record_attempt(ip, success=True):
    now = time.time()
    if success:
        _rate_limit.pop(ip, None)
        return
    attempts = _rate_limit[ip]
    attempts[:] = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    attempts.append(now)

_blocked_ips = {}

def _get_blocked_ips():
    now = time.time()
    for ip, until in list(_blocked_ips.items()):
        if now >= until:
            del _blocked_ips[ip]
    return [{"ip": ip, "remaining": int(until - now)} for ip, until in _blocked_ips.items()]

def _mark_blocked(ip):
    _blocked_ips[ip] = time.time() + RATE_LIMIT_BLOCK

def _unblock_ip(ip):
    _blocked_ips.pop(ip, None)
    _rate_limit.pop(ip, None)

def _get_ip_location(ip):
    if not ip or ip in ("127.0.0.1", "::1", "localhost", "unknown"):
        return "-"
    with _geo_lock:
        cached = _ip_cache.get(ip)
        if cached and time.time() - cached["ts"] < 3600:
            return cached["loc"]
    try:
        r = __import__("httpx").get(f"http://ip-api.com/json/{ip}?fields=city,country,query", timeout=5)
        data = r.json()
        if data.get("city") and data.get("country"):
            loc = f"{data['city']}, {data['country']}"
        elif data.get("country"):
            loc = data["country"]
        else:
            loc = "-"
        with _geo_lock:
            _ip_cache[ip] = {"loc": loc, "ts": time.time()}
        return loc
    except Exception:
        return "-"

def _parse_ua(ua):
    if not ua or ua == "-":
        return "-", "-", "-"
    ua = str(ua)
    os_info = "-"
    app_info = "-"
    device_info = "-"

    # App detection (Wails desktop apps)
    if "ZyperDesktop" in ua or "Wails" in ua:
        app_info = "Zyper Desktop"
    elif "httpx" in ua or "python-requests" in ua or "python-httpx" in ua:
        app_info = "Python Script"
    elif "curl" in ua:
        app_info = "cURL"
    elif "wget" in ua:
        app_info = "wget"
    elif "Go-http-client" in ua:
        app_info = "Go HTTP"
    elif "Postman" in ua:
        app_info = "Postman"
    elif "axios" in ua:
        app_info = "Axios/JS"

    # Browser detection (only if not an app)
    if app_info == "-":
        if "Chrome/" in ua and "Edg/" not in ua and "OPR/" not in ua:
            m = __import__("re").search(r"Chrome/([\d.]+)", ua)
            app_info = f"Chrome {m.group(1)}" if m else "Chrome"
        elif "Edg/" in ua:
            m = __import__("re").search(r"Edg/([\d.]+)", ua)
            app_info = f"Edge {m.group(1)}" if m else "Edge"
        elif "Firefox/" in ua:
            m = __import__("re").search(r"Firefox/([\d.]+)", ua)
            app_info = f"Firefox {m.group(1)}" if m else "Firefox"
        elif "OPR/" in ua or "Opera/" in ua:
            app_info = "Opera"
        elif "Safari/" in ua and "Chrome" not in ua:
            m = __import__("re").search(r"Version/([\d.]+)", ua)
            app_info = f"Safari {m.group(1)}" if m else "Safari"

    # OS detection
    if "Windows NT 10" in ua:
        os_info = "Windows 10"
    elif "Windows NT 11" in ua:
        os_info = "Windows 11"
    elif "Windows NT 6.3" in ua:
        os_info = "Windows 8.1"
    elif "Windows NT 6.1" in ua:
        os_info = "Windows 7"
    elif "Mac OS X" in ua:
        m = __import__("re").search(r"Mac OS X ([\d_]+)", ua)
        os_info = f"macOS {m.group(1).replace('_','.')}" if m else "macOS"
    elif "Android" in ua:
        m = __import__("re").search(r"Android ([\d.]+)", ua)
        os_info = f"Android {m.group(1)}" if m else "Android"
    elif "iPhone" in ua or "iPad" in ua:
        m = __import__("re").search(r"iPhone OS ([\d_]+)", ua)
        os_info = f"iOS {m.group(1).replace('_','.')}" if m else "iOS"
    elif "Linux" in ua:
        os_info = "Linux"

    # Device model
    if "iPhone" in ua:
        m = __import__("re").search(r"iPhone(\d+,\d+)?", ua)
        device_info = f"iPhone {m.group(0).replace(',',' ')}" if m else "iPhone"
    elif "iPad" in ua:
        device_info = "iPad"
    elif "SM-" in ua:
        m = __import__("re").search(r"SM-([A-Za-z0-9]+)", ua)
        device_info = f"Samsung {m.group(1)}" if m else "Samsung"
    elif "Pixel" in ua:
        m = __import__("re").search(r"Pixel [\d]+", ua)
        device_info = m.group(0) if m else "Google Pixel"
    elif "MI" in ua or "Redmi" in ua or "Xiaomi" in ua:
        device_info = "Xiaomi"
    elif "OPPO" in ua or "CPH" in ua:
        device_info = "OPPO"
    elif "vivo" in ua or __import__("re").search(r"\bV\d{4}\b", ua):
        device_info = "vivo"
    elif "OnePlus" in ua:
        device_info = "OnePlus"
    elif "ZyperDesktop" in ua or "Wails" in ua:
        device_info = "Desktop App"
    elif "Macintosh" in ua:
        device_info = "Mac"
    elif "Windows" in ua:
        device_info = "PC"
    elif "Linux" in ua and "Android" not in ua:
        device_info = "Linux PC"

    return os_info, app_info, device_info

async def _log_audit(action, hwid, key, ip, user_agent, success, reason=""):
    if db is None:
        return
    try:
        await db.audit_logs.insert_one({
            "action": action,
            "hwid": hwid,
            "key": key,
            "ip": ip,
            "user_agent": user_agent,
            "success": success,
            "reason": reason,
            "timestamp": datetime.utcnow(),
        })
    except Exception:
        pass


def _fetch_endpoint(path, method="GET"):
    try:
        url = REAL_BASE + path
        resp = httpx.get(url, timeout=15, follow_redirects=True, verify=False)
        with _cache_lock:
            _cache[path] = (resp.status_code, dict(resp.headers), resp.content)
        return True
    except Exception:
        return False


def _refresh_cache_loop():
    while True:
        for path in ENDPOINTS:
            _fetch_endpoint(path)
        time.sleep(120)


def _get_cached(path):
    with _cache_lock:
        return _cache.get(path)


def _get_client_ip(request: Request):
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    rip = request.headers.get("x-real-ip")
    if rip:
        return rip
    return request.client.host if request.client else "unknown"


def generate_key():
    return f"ZYPER-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"


async def _cleanup_loop():
    while True:
        await asyncio.sleep(3600)
        if db is None:
            continue
        try:
            cutoff = datetime.utcnow() - timedelta(days=7)
            await db.sessions.delete_many({"last_seen": {"$lt": cutoff}})
            cutoff_expired = datetime.utcnow() - timedelta(days=30)
            await db.keys.delete_many({"expires_at": {"$lt": cutoff_expired, "$exists": True}})
            cutoff_audit = datetime.utcnow() - timedelta(days=14)
            await db.audit_logs.delete_many({"timestamp": {"$lt": cutoff_audit}})
        except Exception:
            pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, client
    if MONGO_URI:
        client = AsyncIOMotorClient(MONGO_URI)
        db = client.zyper_auth
        await db.keys.create_index("key", unique=True)
        await db.sessions.create_index("hwid")
        await db.audit_logs.create_index("timestamp")
        await db.audit_logs.create_index("ip")
    asyncio.create_task(_cleanup_loop())
    bg = threading.Thread(target=_refresh_cache_loop, daemon=True)
    bg.start()
    for path in ENDPOINTS:
        _fetch_endpoint(path)
    yield
    if client:
        client.close()


app = FastAPI(title="Zyper Auth Server", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/dashboard") and not path.startswith("/health"):
        ip = _get_client_ip(request)
        print(f"[REQ] {request.method} {path} from={ip}", flush=True)
    response = await call_next(request)
    return response


def _is_admin(request: Request):
    return request.cookies.get("admin_token") == ADMIN_PASSWORD


@app.post("/v1/license/validate")
async def license_validate(request: Request):
    body = await request.body()
    data = {}
    if body:
        try:
            data = json.loads(body)
        except Exception:
            pass

    req_hwid = data.get("hwid", "")
    req_key = data.get("key", "")
    client_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    if not _check_rate_limit(client_ip):
        await _log_audit("validate", req_hwid, req_key, client_ip, user_agent, False, "rate limited")
        return JSONResponse({"ok": False, "state": "invalid", "error": "too many attempts"})

    if not req_hwid:
        return JSONResponse({"ok": False, "state": "invalid", "error": "no hwid"})

    if db is None:
        return JSONResponse({"ok": False, "state": "invalid", "error": "no database"})

    if kill_switch:
        await _log_audit("validate", req_hwid, req_key, client_ip, user_agent, False, "kill switch")
        return JSONResponse({"ok": False, "state": "invalid", "error": "system offline"})

    if req_key:
        key_doc = await db.keys.find_one({"key": req_key})
        if not key_doc:
            _record_attempt(client_ip, False)
            await _log_audit("validate", req_hwid, req_key, client_ip, user_agent, False, "invalid key")
            return JSONResponse({"ok": False, "state": "invalid", "error": "invalid key"})

        if key_doc.get("disabled"):
            _record_attempt(client_ip, False)
            await _log_audit("validate", req_hwid, req_key, client_ip, user_agent, False, "key revoked")
            return JSONResponse({"ok": False, "state": "invalid", "error": "key revoked"})

        if key_doc.get("expires_at") and datetime.utcnow() > key_doc["expires_at"]:
            _record_attempt(client_ip, False)
            await _log_audit("validate", req_hwid, req_key, client_ip, user_agent, False, "key expired")
            return JSONResponse({"ok": False, "state": "invalid", "error": "key expired"})

        existing_session = await db.sessions.find_one({"hwid": req_hwid})
        if existing_session and not existing_session.get("active", True):
            _record_attempt(client_ip, False)
            await _log_audit("validate", req_hwid, req_key, client_ip, user_agent, False, "device kicked")
            return JSONResponse({"ok": False, "state": "invalid", "error": "device kicked by admin"})

        max_devices = key_doc.get("max_devices", 1)
        bound_hwids = await db.sessions.distinct("hwid", {"bound_key": req_key, "active": True})
        if req_hwid not in bound_hwids and len(bound_hwids) >= max_devices:
            _record_attempt(client_ip, False)
            await _log_audit("validate", req_hwid, req_key, client_ip, user_agent, False, "max devices")
            return JSONResponse({"ok": False, "state": "invalid", "error": "max devices reached"})

        await db.sessions.update_one(
            {"hwid": req_hwid},
            {"$set": {
                "hwid": req_hwid,
                "ip": client_ip,
                "user_agent": user_agent,
                "bound_key": req_key,
                "last_seen": datetime.utcnow(),
                "active": True,
                "first_seen": datetime.utcnow(),
            },
            "$setOnInsert": {"created_at": datetime.utcnow()}},
            upsert=True,
        )

        _record_attempt(client_ip, True)
        await _log_audit("validate", req_hwid, req_key, client_ip, user_agent, True, "ok")
        return JSONResponse({
            "ok": True,
            "state": "valid",
            "hwid": req_hwid,
            "hasKey": True,
            "key": req_key,
            "expires_at": key_doc["expires_at"].isoformat() if key_doc.get("expires_at") else None,
        })

    session = await db.sessions.find_one({"hwid": req_hwid})
    if session and session.get("bound_key"):
        if not session.get("active", True):
            _record_attempt(client_ip, False)
            await _log_audit("validate", req_hwid, "", client_ip, user_agent, False, "device kicked")
            return JSONResponse({"ok": False, "state": "invalid", "error": "device kicked by admin"})

        bound_key = await db.keys.find_one({"key": session["bound_key"]})
        if bound_key and not bound_key.get("disabled"):
            if bound_key.get("expires_at") and datetime.utcnow() > bound_key["expires_at"]:
                return JSONResponse({"ok": False, "state": "invalid", "error": "key expired"})

            await db.sessions.update_one(
                {"hwid": req_hwid},
                {"$set": {"last_seen": datetime.utcnow(), "ip": client_ip, "user_agent": user_agent}}
            )

            _record_attempt(client_ip, True)
            return JSONResponse({
                "ok": True,
                "state": "valid",
                "hwid": req_hwid,
                "hasKey": True,
                "key": session["bound_key"],
                "expires_at": bound_key["expires_at"].isoformat() if bound_key.get("expires_at") else None,
            })

    await _log_audit("validate", req_hwid, "", client_ip, user_agent, False, "pending")
    return JSONResponse({"ok": False, "state": "pending", "error": "enter license key"})


@app.post("/v1/license/activate")
async def license_activate(request: Request):
    body = await request.body()
    data = {}
    if body:
        try:
            data = json.loads(body)
        except Exception:
            pass

    req_hwid = data.get("hwid", "")
    req_key = data.get("key", "")
    client_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    if not _check_rate_limit(client_ip):
        await _log_audit("activate", req_hwid, req_key, client_ip, user_agent, False, "rate limited")
        return JSONResponse({"ok": False, "state": "invalid", "error": "too many attempts"})

    if not req_hwid:
        return JSONResponse({"ok": False, "error": "no hwid"})

    if db is None:
        return JSONResponse({"ok": False, "error": "no database"})

    if kill_switch:
        await _log_audit("activate", req_hwid, req_key, client_ip, user_agent, False, "kill switch")
        return JSONResponse({"ok": False, "error": "system offline"})

    if not req_key:
        return JSONResponse({"ok": False, "state": "pending", "error": "enter license key"})

    key_doc = await db.keys.find_one({"key": req_key})
    if not key_doc:
        _record_attempt(client_ip, False)
        await _log_audit("activate", req_hwid, req_key, client_ip, user_agent, False, "invalid key")
        return JSONResponse({"ok": False, "state": "invalid", "error": "invalid key"})

    if key_doc.get("disabled"):
        _record_attempt(client_ip, False)
        await _log_audit("activate", req_hwid, req_key, client_ip, user_agent, False, "key revoked")
        return JSONResponse({"ok": False, "state": "invalid", "error": "key revoked"})

    if key_doc.get("expires_at") and datetime.utcnow() > key_doc["expires_at"]:
        _record_attempt(client_ip, False)
        await _log_audit("activate", req_hwid, req_key, client_ip, user_agent, False, "key expired")
        return JSONResponse({"ok": False, "state": "invalid", "error": "key expired"})

    existing_session = await db.sessions.find_one({"hwid": req_hwid})
    if existing_session and not existing_session.get("active", True):
        _record_attempt(client_ip, False)
        await _log_audit("activate", req_hwid, req_key, client_ip, user_agent, False, "device kicked")
        return JSONResponse({"ok": False, "state": "invalid", "error": "device kicked by admin"})

    max_devices = key_doc.get("max_devices", 1)
    bound_hwids = await db.sessions.distinct("hwid", {"bound_key": req_key})
    if req_hwid not in bound_hwids and len(bound_hwids) >= max_devices:
        _record_attempt(client_ip, False)
        await _log_audit("activate", req_hwid, req_key, client_ip, user_agent, False, "max devices")
        return JSONResponse({"ok": False, "state": "invalid", "error": "max devices reached"})

    await db.sessions.update_one(
        {"hwid": req_hwid},
        {"$set": {
            "hwid": req_hwid,
            "ip": client_ip,
            "user_agent": user_agent,
            "bound_key": req_key,
            "last_seen": datetime.utcnow(),
            "active": True,
            "first_seen": datetime.utcnow(),
        },
        "$setOnInsert": {"created_at": datetime.utcnow()}} ,
        upsert=True,
    )

    await db.keys.update_one(
        {"key": req_key},
        {"$set": {"last_used": datetime.utcnow(), "used_by_hwid": req_hwid}}
    )

    _record_attempt(client_ip, True)
    await _log_audit("activate", req_hwid, req_key, client_ip, user_agent, True, "ok")
    return JSONResponse({
        "ok": True,
        "state": "valid",
        "hwid": req_hwid,
        "key": req_key,
    })


@app.get("/v1/modules")
async def get_modules(request: Request):
    check = await _check_heartbeat(request)
    if not check:
        return JSONResponse({"modules": []})
    cached = _get_cached("/v1/modules")
    if cached:
        return JSONResponse(json.loads(cached[2]))
    return JSONResponse({"modules": []})


@app.get("/v1/social-modules")
async def get_social_modules(request: Request):
    check = await _check_heartbeat(request)
    if not check:
        return JSONResponse({"modules": []})
    cached = _get_cached("/v1/social-modules")
    if cached:
        return JSONResponse(json.loads(cached[2]))
    return JSONResponse({"modules": []})


@app.get("/v1/checker-modules")
async def get_checker_modules(request: Request):
    check = await _check_heartbeat(request)
    if not check:
        return JSONResponse({"modules": []})
    cached = _get_cached("/v1/checker-modules")
    if cached:
        return JSONResponse(json.loads(cached[2]))
    return JSONResponse({"modules": []})


async def _check_heartbeat(request: Request) -> bool:
    if kill_switch:
        return False
    if db is None:
        return True
    hwid = request.headers.get("x-hwid", "")
    if not hwid:
        return True
    session = await db.sessions.find_one({"hwid": hwid})
    if not session:
        return True
    if session.get("bound_key"):
        key_doc = await db.keys.find_one({"key": session["bound_key"]})
        if key_doc and key_doc.get("disabled"):
            return False
    return True


@app.api_route("/v1/telemetry", methods=["GET", "POST", "OPTIONS"])
async def telemetry(request: Request):
    return JSONResponse({"ok": True})


@app.api_route("/v1/manifest", methods=["GET", "POST", "OPTIONS"])
async def manifest(request: Request):
    return JSONResponse({"ok": False, "error": "no updates available"})


@app.api_route("/v1/assets/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def assets(path: str):
    return JSONResponse({"ok": True})


@app.api_route("/v1/extensions/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def extensions(path: str):
    return JSONResponse({"ok": True})


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def api_catch_all(path: str, request: Request):
    return JSONResponse({"ok": True})


@app.get("/")
async def root_redirect():
    return RedirectResponse(url="https://t.me/Fetuseater005", status_code=302)


@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


DASHBOARD_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zyper Auth Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#e0e0e0;font-family:'Segoe UI',monospace;min-height:100vh}
.hdr{background:#111;border-bottom:1px solid #333;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.hdr h1{color:#00ff88;font-size:18px}
.stats{display:flex;gap:12px;flex-wrap:wrap}
.st{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:8px 14px;text-align:center}
.st .n{font-size:22px;font-weight:bold;color:#00ff88}
.st .l{font-size:10px;color:#888;text-transform:uppercase}
.ct{max-width:1400px;margin:16px auto;padding:0 16px}
.sec{background:#111;border:1px solid #333;border-radius:8px;margin-bottom:16px;overflow:hidden}
.sh{background:#1a1a1a;padding:10px 14px;border-bottom:1px solid #333;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.sh h2{font-size:13px;color:#00ff88}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 14px;font-size:11px;color:#888;text-transform:uppercase;border-bottom:1px solid #333}
td{padding:8px 14px;font-size:12px;border-bottom:1px solid #222}
tr:hover{background:#1a1a1a}
.s{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:bold;text-transform:uppercase;display:inline-block}
.s.active{background:#003322;color:#00ff88}
.s.disabled{background:#330000;color:#ff4444}
.s.expired{background:#332200;color:#ffaa00}
.s.kicked{background:#330000;color:#ff4444}
.b{padding:6px 14px;border:none;border-radius:4px;font-size:11px;cursor:pointer;font-weight:bold;text-decoration:none;display:inline-block}
.b.gen{background:#00ff88;color:#000}
.b.dl{background:#333;color:#fff}
.b.bl{background:#ff4444;color:#fff}
.b.grn{background:#00ff88;color:#000}
.b.cp{background:#555;color:#fff;padding:4px 8px;font-size:10px;margin-left:4px}
.b.ext{background:#ffaa00;color:#000;padding:4px 8px;font-size:10px}
.b:hover{opacity:.85}
.gen-form{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 14px}
.gen-form input,.gen-form select,.ext-input{background:#0a0a0a;color:#fff;border:1px solid #333;padding:6px 10px;border-radius:4px;font-size:12px}
.gen-form label{font-size:11px;color:#888}
.kc{font-family:monospace;color:#00ff88;letter-spacing:1px}
.ts{font-size:10px;color:#666}
.on{color:#00ff88}.off{color:#ff4444}
.info{font-size:10px;color:#555;padding:4px 14px}
.sbar{background:#0a0a0a;color:#fff;border:1px solid #333;padding:6px 10px;border-radius:4px;font-size:12px;width:200px;margin:8px 14px}
.toast{position:fixed;bottom:20px;right:20px;background:#00ff88;color:#000;padding:10px 20px;border-radius:6px;font-size:13px;font-weight:bold;opacity:0;transition:opacity .3s;z-index:999}
.toast.show{opacity:1}
</style></head><body>
<div class="toast" id="toast">Copied!</div>
<div class="hdr"><h1>Zyper Auth Dashboard</h1>
<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
<div class="stats">
<div class="st"><div class="n">KEYS_STAT1</div><div class="l">keys</div></div>
<div class="st"><div class="n" style="color:#00ff88">ACTIVE_USERS</div><div class="l">active users</div></div>
<div class="st"><div class="n" style="color:#ffaa00">KEYS_STAT2</div><div class="l">active/expired</div></div>
<div class="st"><div class="n" style="color:#00ff88">KICKED_USERS</div><div class="l">kicked</div></div>
</div>
<form method="POST" action="/dashboard/refresh" style="display:inline"><button class="b gen" type="submit">Refresh Modules</button></form>
<form method="POST" action="/dashboard/killswitch" style="display:inline"><button class="b KS_CLASS" type="submit">KS_LABEL</button></form>
<a href="/dashboard/history" style="color:#888;text-decoration:none;font-size:12px;margin-right:8px">History</a>
<a href="/dashboard/logout" style="color:#ff4444;text-decoration:none;font-size:12px;font-weight:bold">Logout</a>
</div></div>
<div class="ct">

<div class="sec"><div class="sh"><h2>Generate New Key</h2></div>
<form method="POST" action="/dashboard/generate" class="gen-form">
<label>Days:</label><input type="number" name="days" value="30" min="1" max="365" style="width:60px">
<label>Max Devices:</label><input type="number" name="max_devices" value="1" min="1" max="10" style="width:60px">
<label>Note:</label><input type="text" name="note" placeholder="optional note" style="width:200px">
<label>Count:</label><input type="number" name="count" value="1" min="1" max="20" style="width:60px">
<button class="b gen" type="submit">Generate Keys</button>
</form>
NEW_KEYS
</div>

<div class="sec"><div class="sh"><h2>Active Users</h2><input class="sbar" id="userSearch" placeholder="Search users..." oninput="filterTable('userSearch','userTable')"></div>
<table id="userTable"><tr><th>HWID</th><th>Key</th><th>IP</th><th>Device</th><th>User Agent</th><th>First Seen</th><th>Last Seen</th><th>Note</th><th>Status</th><th>Actions</th></tr>
USER_ROWS
</table></div>

<div class="sec"><div class="sh"><h2>All Keys</h2><input class="sbar" id="keySearch" placeholder="Search keys..." oninput="filterTable('keySearch','keyTable')"></div>
<table id="keyTable"><tr><th>Key</th><th>Status</th><th>Devices</th><th>Expires</th><th>Note</th><th>Created</th><th>Actions</th></tr>
KEY_ROWS
</table></div>

<div class="sec"><div class="sh"><h2>Blocked IPs (Rate Limited)</h2></div>
<table><tr><th>IP</th><th>Time Remaining</th><th>Actions</th></tr>
BLOCKED_ROWS
</table></div>

</div>
<script>
function cp(t){navigator.clipboard.writeText(t);var d=document.getElementById('toast');d.textContent='Copied: '+t.slice(0,16)+'...';d.classList.add('show');setTimeout(function(){d.classList.remove('show')},1500)}
function filterTable(inputId,tableId){var q=document.getElementById(inputId).value.toLowerCase();var r=document.getElementById(tableId).rows;for(var i=1;i<r.length;i++){var match=false;for(var j=0;j<r[i].cells.length;j++){if(r[i].cells[j].textContent.toLowerCase().includes(q)){match=true;break}}r[i].style.display=match?'':'none'}}
setTimeout(function(){location.reload()},15000)
</script>
</body></html>"""


@app.post("/dashboard/login")
async def dashboard_login(request: Request, password: str = Form(...)):
    if password != ADMIN_PASSWORD:
        return HTMLResponse("""<html><head><title>Zyper Auth</title>
<style>body{background:#0a0a0a;color:#fff;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.l{background:#111;padding:40px;border:1px solid #333;border-radius:8px;text-align:center}
input{background:#1a1a1a;color:#fff;border:1px solid #333;padding:12px;font-size:16px;border-radius:4px;width:250px}
button{background:#00ff88;color:#000;border:none;padding:12px 30px;font-size:16px;border-radius:4px;cursor:pointer;margin-top:10px;font-weight:bold}
.err{color:#ff4444;margin-bottom:10px}</style></head>
<body><div class="l"><h2>Zyper Auth</h2><br><p class="err">Wrong password</p>
<form method="POST" action="/dashboard/login"><input type="password" name="password" placeholder="Password" autofocus><br><br>
<button type="submit">Login</button></form></div></body></html>""")
    resp = RedirectResponse(url="/dashboard", status_code=302)
    resp.set_cookie("admin_token", ADMIN_PASSWORD, httponly=True, samesite="lax", max_age=86400)
    return resp


@app.get("/dashboard/logout")
async def dashboard_logout():
    resp = RedirectResponse(url="/dashboard", status_code=302)
    resp.delete_cookie("admin_token")
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not _is_admin(request):
        return HTMLResponse("""<html><head><title>Zyper Auth</title>
<style>body{background:#0a0a0a;color:#fff;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.l{background:#111;padding:40px;border:1px solid #333;border-radius:8px;text-align:center}
input{background:#1a1a1a;color:#fff;border:1px solid #333;padding:12px;font-size:16px;border-radius:4px;width:250px}
button{background:#00ff88;color:#000;border:none;padding:12px 30px;font-size:16px;border-radius:4px;cursor:pointer;margin-top:10px;font-weight:bold}</style></head>
<body><div class="l"><h2>Zyper Auth</h2><br>
<form method="POST" action="/dashboard/login"><input type="password" name="password" placeholder="Password" autofocus><br><br>
<button type="submit">Login</button></form></div></body></html>""")

    if db is None:
        return HTMLResponse("<h1 style='color:red'>Database not connected</h1>")

    keys = await db.keys.find().sort("created_at", -1).to_list(200)
    sessions = await db.sessions.find().sort("last_seen", -1).to_list(200)

    total_keys = len(keys)
    active_keys = sum(1 for k in keys if not k.get("disabled") and not (k.get("expires_at") and datetime.utcnow() > k["expires_at"]))
    expired_keys = sum(1 for k in keys if k.get("expires_at") and datetime.utcnow() > k["expires_at"])
    active_users = sum(1 for s in sessions if s.get("active") and s.get("bound_key"))
    kicked_users = sum(1 for s in sessions if not s.get("active") and s.get("bound_key"))

    key_rows = ""
    for k in keys:
        status = "disabled" if k.get("disabled") else ("expired" if k.get("expires_at") and datetime.utcnow() > k["expires_at"] else "active")
        exp = k["expires_at"].strftime("%d %b %Y %H:%M") if k.get("expires_at") else "never"
        created = k["created_at"].strftime("%d %b %Y %H:%M") if k.get("created_at") else "-"
        note = k.get("note", "") or "-"
        maxd = k.get("max_devices", 1)
        key_rows += f"""<tr><td class="kc">{k['key']} <button class="b cp" onclick="cp('{k['key']}')">Copy</button></td>
        <td><span class="s {status}">{status}</span></td>
        <td>{maxd}</td><td style="font-size:10px">{exp}</td>
        <td style="font-size:10px">{note}</td><td class="ts">{created}</td>
        <td>
        <form method="POST" action="/dashboard/toggle-key" style="display:inline"><input type="hidden" name="key" value="{k['key']}"><button class="b {'bl' if status=='active' else 'grn'}" type="submit">{'Revoke' if status=='active' else 'Enable'}</button></form>
        <form method="POST" action="/dashboard/extend-key" style="display:inline"><input class="ext-input" type="number" name="days" value="1" min="1" max="365" style="width:50px"><input type="hidden" name="key" value="{k['key']}"><button class="b ext" type="submit">Extend</button></form>
        <form method="POST" action="/dashboard/delete-key" style="display:inline"><input type="hidden" name="key" value="{k['key']}"><button class="b dl" type="submit">Del</button></form>
        </td></tr>"""

    if not key_rows:
        key_rows = '<tr><td colspan="7" style="text-align:center;color:#555;padding:16px">No keys generated yet</td></tr>'

    user_rows = ""
    for s in sessions:
        key = s.get("bound_key", "")
        if not key:
            continue
        active = s.get("active", True)
        hwid = s.get("hwid", "-")
        ip = s.get("ip", "-")
        ua = s.get("user_agent", "-")
        os_info, browser_info, device_info = _parse_ua(ua)
        ip_loc = _get_ip_location(ip)
        ip_display = f"{ip}<br><span style='font-size:9px;color:#888'>{ip_loc}</span>" if ip_loc != "-" else ip
        device_tag = f"{os_info} / {app_info} / {device_info}".replace(" / - / ", " ").replace(" / -", "").replace("- / ", "")
        first = s["first_seen"].strftime("%d %b %H:%M") if s.get("first_seen") else "-"
        last = s["last_seen"].strftime("%d %b %H:%M") if s.get("last_seen") else "-"
        key_note = ""
        if key and key != "-":
            kd = await db.keys.find_one({"key": key})
            key_note = kd.get("note", "") if kd else ""
        status_label = "active" if active else "kicked"
        status_color = "active" if active else "kicked"
        user_rows += f"""<tr>
        <td style="font-size:10px;word-break:break-all">{hwid}</td>
        <td class="kc" style="font-size:10px">{key}</td>
        <td style="font-size:11px">{ip_display}</td>
        <td style="font-size:10px" title="{ua}">{device_tag}</td>
        <td style="font-size:9px;max-width:200px;overflow:hidden;text-overflow:ellipsis">{ua}</td>
        <td class="ts">{first}</td><td class="ts">{last}</td>
        <td style="font-size:10px">{key_note or '-'}</td>
        <td><span class="s {status_color}">{status_label}</span></td>
        <td>
        {f'<form method="POST" action="/dashboard/kick" style="display:inline"><input type="hidden" name="hwid" value="{hwid}"><button class="b bl" type="submit">Kick</button></form>' if active else ''}
        {f'<form method="POST" action="/dashboard/unkick" style="display:inline"><input type="hidden" name="hwid" value="{hwid}"><button class="b grn" type="submit">Unkick</button></form>' if not active else ''}
        </td></tr>"""

    if not user_rows:
        user_rows = '<tr><td colspan="10" style="text-align:center;color:#555;padding:16px">No users yet</td></tr>'

    blocked = _get_blocked_ips()
    blocked_rows = ""
    for b in blocked:
        mins = b["remaining"] // 60
        secs = b["remaining"] % 60
        blocked_rows += f"""<tr>
        <td>{b['ip']}</td>
        <td>{mins}m {secs}s</td>
        <td><form method="POST" action="/dashboard/unban-ip" style="display:inline"><input type="hidden" name="ip" value="{b['ip']}"><button class="b grn" type="submit">Unban</button></form></td></tr>"""

    if not blocked_rows:
        blocked_rows = '<tr><td colspan="3" style="text-align:center;color:#555;padding:16px">No blocked IPs</td></tr>'

    html = DASHBOARD_HTML.replace("KEY_ROWS", key_rows).replace("USER_ROWS", user_rows).replace("BLOCKED_ROWS", blocked_rows)
    html = html.replace("KEYS_STAT1", str(total_keys)).replace("ACTIVE_USERS", str(active_users))
    html = html.replace("KEYS_STAT2", f"{active_keys}/{expired_keys}").replace("KICKED_USERS", str(kicked_users))
    html = html.replace("KS_CLASS", "bl" if kill_switch else "grn").replace("KS_LABEL", "KILL: ON" if kill_switch else "KILL: OFF")
    html = html.replace("NEW_KEYS", "")
    return HTMLResponse(html)


@app.post("/dashboard/generate")
async def generate_keys(request: Request, days: int = Form(30), max_devices: int = Form(1), note: str = Form(""), count: int = Form(1)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")

    generated = []
    for _ in range(min(count, 20)):
        key = generate_key()
        expires = datetime.utcnow() + timedelta(days=days)
        await db.keys.insert_one({
            "key": key,
            "max_devices": max_devices,
            "expires_at": expires,
            "note": note,
            "disabled": False,
            "created_at": datetime.utcnow(),
            "last_used": None,
            "used_by_hwid": None,
        })
        generated.append(key)

    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/toggle-key")
async def toggle_key(request: Request, key: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    key_doc = await db.keys.find_one({"key": key})
    if not key_doc:
        raise HTTPException(404, "Key not found")
    new_disabled = not key_doc.get("disabled", False)
    await db.keys.update_one({"key": key}, {"$set": {"disabled": new_disabled}})

    if new_disabled:
        await db.sessions.update_many({"bound_key": key}, {"$set": {"active": False}})

    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/delete-key")
async def delete_key(request: Request, key: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.keys.delete_one({"key": key})
    await db.sessions.delete_many({"bound_key": key})
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/kick")
async def kick_user(request: Request, hwid: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.sessions.update_one({"hwid": hwid}, {"$set": {"active": False}})
    await _log_audit("kick", hwid, "", _get_client_ip(request), request.headers.get("user-agent",""), True, "user kicked")
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/unkick")
async def unkick_user(request: Request, hwid: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.sessions.update_one({"hwid": hwid}, {"$set": {"active": True}})
    await _log_audit("unkick", hwid, "", _get_client_ip(request), request.headers.get("user-agent",""), True, "user unkicked")
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/unban-ip")
async def unban_ip(request: Request, ip: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    _unblock_ip(ip)
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/killswitch")
async def toggle_killswitch(request: Request):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    global kill_switch
    kill_switch = not kill_switch
    if kill_switch and db:
        await db.sessions.update_many({}, {"$set": {"active": False}})
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/extend-key")
async def extend_key(request: Request, key: str = Form(...), days: int = Form(1)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    key_doc = await db.keys.find_one({"key": key})
    if not key_doc:
        raise HTTPException(404, "Key not found")
    current_exp = key_doc.get("expires_at")
    if current_exp:
        if current_exp < datetime.utcnow():
            new_exp = datetime.utcnow() + timedelta(days=days)
        else:
            new_exp = current_exp + timedelta(days=days)
    else:
        new_exp = datetime.utcnow() + timedelta(days=days)
    await db.keys.update_one({"key": key}, {"$set": {"expires_at": new_exp, "disabled": False}})
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/refresh")
async def refresh_cache(request: Request):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    for path in ENDPOINTS:
        _fetch_endpoint(path)
    return RedirectResponse(url="/dashboard", status_code=302)


HISTORY_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zyper Auth - History</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#e0e0e0;font-family:'Segoe UI',monospace}
.hdr{background:#111;border-bottom:1px solid #333;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.hdr h1{color:#00ff88;font-size:18px}
.hdr a{color:#888;text-decoration:none;font-size:12px}
.hdr a:hover{color:#00ff88}
.ct{max-width:1400px;margin:16px auto;padding:0 16px}
.sec{background:#111;border:1px solid #333;border-radius:8px;margin-bottom:16px;overflow:hidden}
.sh{background:#1a1a1a;padding:10px 14px;border-bottom:1px solid #333}
.sh h2{font-size:13px;color:#00ff88}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 14px;font-size:11px;color:#888;text-transform:uppercase;border-bottom:1px solid #333}
td{padding:6px 14px;font-size:11px;border-bottom:1px solid #222;word-break:break-all}
tr:hover{background:#1a1a1a}
.s{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:bold;text-transform:uppercase;display:inline-block}
.s.active{background:#003322;color:#00ff88}
.s.disabled{background:#330000;color:#ff4444}
.s.kicked{background:#330000;color:#ff4444}
.sb{background:#0a0a0a;color:#fff;border:1px solid #333;padding:6px 10px;border-radius:4px;font-size:12px;width:200px;margin:8px 14px}
.ts{font-size:10px;color:#666}
a{color:#00ff88}
</style></head><body>
<div class="hdr"><h1>Activity History</h1><a href="/dashboard">&larr; Back to Dashboard</a></div>
<div class="ct">

<div class="sec"><div class="sh"><h2>Audit Logs</h2><input class="sb" id="auditSearch" placeholder="Search..." oninput="filterTable('auditSearch','auditTable')"></div>
<table id="auditTable"><tr><th>Time</th><th>Action</th><th>HWID</th><th>Key</th><th>IP</th><th>User Agent</th><th>Status</th><th>Reason</th></tr>
AUDIT_ROWS
</table></div>

<div class="sec"><div class="sh"><h2>All Past Users (with bound keys)</h2><input class="sb" id="pastSearch" placeholder="Search..." oninput="filterTable('pastSearch','pastTable')"></div>
<table id="pastTable"><tr><th>HWID</th><th>Key</th><th>IP</th><th>Device</th><th>User Agent</th><th>First Seen</th><th>Last Seen</th><th>Status</th></tr>
PAST_ROWS
</table></div>

</div>
<script>
function filterTable(i,t){var q=document.getElementById(i).value.toLowerCase();var r=document.getElementById(t).rows;for(var j=1;j<r.length;j++){var m=false;for(var k=0;k<r[j].cells.length;k++){if(r[j].cells[k].textContent.toLowerCase().includes(q)){m=true;break}}r[j].style.display=m?'':'none'}}
setTimeout(function(){location.reload()},30000)
</script>
</body></html>"""


@app.get("/dashboard/history", response_class=HTMLResponse)
async def dashboard_history(request: Request):
    if not _is_admin(request):
        return HTMLResponse("<h2 style='color:red'>Unauthorized</h2>")
    if db is None:
        return HTMLResponse("<h2 style='color:red'>No database</h2>")

    audit_logs = await db.audit_logs.find().sort("timestamp", -1).to_list(500)
    past_sessions = await db.sessions.find({"bound_key": {"$ne": ""}}).sort("last_seen", -1).to_list(500)

    audit_rows = ""
    for a in audit_logs:
        ts = a["timestamp"].strftime("%d %b %H:%M:%S") if a.get("timestamp") else "-"
        action = a.get("action", "-")
        hwid = (a.get("hwid", "-") or "-")[:40]
        key = (a.get("key", "-") or "-")[:20]
        ip = a.get("ip", "-") or "-"
        ua = (a.get("user_agent", "-") or "-")[:40]
        success = a.get("success", False)
        reason = a.get("reason", "") or ""
        status_cls = "active" if success else "disabled"
        status_txt = "Success" if success else "Failed"
        ip_loc = _get_ip_location(ip)
        ip_display = f"{ip}<br><span style='font-size:9px;color:#888'>{ip_loc}</span>" if ip_loc != "-" else ip
        audit_rows += f"""<tr>
        <td class="ts">{ts}</td>
        <td>{action}</td>
        <td style="font-size:10px">{hwid}</td>
        <td style="font-size:10px;color:#00ff88">{key}</td>
        <td style="font-size:11px">{ip_display}</td>
        <td style="font-size:9px">{ua}</td>
        <td><span class="s {status_cls}">{status_txt}</span></td>
        <td>{reason}</td></tr>"""

    if not audit_rows:
        audit_rows = '<tr><td colspan="8" style="text-align:center;color:#555;padding:16px">No audit logs yet</td></tr>'

    past_rows = ""
    for s in past_sessions:
        active = s.get("active", True)
        hwid = s.get("hwid", "-") or "-"
        key = s.get("bound_key", "-") or "-"
        ip = s.get("ip", "-") or "-"
        ua = s.get("user_agent", "-") or "-"
        os_info, browser_info, device_info = _parse_ua(ua)
        device_tag = f"{os_info} / {app_info} / {device_info}".replace(" / - / ", " ").replace(" / -", "").replace("- / ", "")
        ip_loc = _get_ip_location(ip)
        ip_display = f"{ip}<br><span style='font-size:9px;color:#888'>{ip_loc}</span>" if ip_loc != "-" else ip
        first = s["first_seen"].strftime("%d %b %H:%M") if s.get("first_seen") else "-"
        last = s["last_seen"].strftime("%d %b %H:%M") if s.get("last_seen") else "-"
        status_cls = "active" if active else "kicked"
        status_txt = "Active" if active else "Kicked"
        past_rows += f"""<tr>
        <td style="font-size:10px">{hwid}</td>
        <td style="font-size:10px;color:#00ff88">{key}</td>
        <td style="font-size:11px">{ip_display}</td>
        <td style="font-size:10px" title="{ua}">{device_tag}</td>
        <td style="font-size:9px;max-width:200px;overflow:hidden;text-overflow:ellipsis">{ua}</td>
        <td class="ts">{first}</td><td class="ts">{last}</td>
        <td><span class="s {status_cls}">{status_txt}</span></td></tr>"""

    if not past_rows:
        past_rows = '<tr><td colspan="8" style="text-align:center;color:#555;padding:16px">No past users</td></tr>'

    html = HISTORY_HTML.replace("AUDIT_ROWS", audit_rows).replace("PAST_ROWS", past_rows)
    return HTMLResponse(html)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
