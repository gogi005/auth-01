import os, re, json, time, asyncio, uuid, secrets, threading, html as html_mod
import httpx
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from collections import defaultdict

import traceback
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

        existing = await db.sessions.find_one({"hwid": req_hwid})
        if existing:
            await db.sessions.update_one(
                {"hwid": req_hwid},
                {"$set": {"last_seen": datetime.utcnow(), "ip": client_ip, "user_agent": user_agent}}
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
    bound_hwids = await db.sessions.distinct("hwid", {"bound_key": req_key, "active": True})
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
    modules = []
    if cached:
        modules = json.loads(cached[2]).get("modules", [])
    modules = await _inject_custom_modules(modules, "onchain")
    return JSONResponse({"modules": modules})


async def _inject_custom_modules(modules, kind_filter=None):
    if db is None:
        return modules
    try:
        existing_ids = {m["id"] for m in modules if "id" in m}
        custom = await db.custom_modules.find().to_list(100) if db is not None else []
        for c in custom:
            m = {k: v for k, v in c.items() if k != "_id"}
            if not m.get("id"):
                continue
            if m["id"] in existing_ids:
                continue
            if kind_filter == "social" and m.get("kind") != "http":
                continue
            if kind_filter == "onchain" and m.get("kind") == "http":
                continue
            modules.append(m)
    except Exception:
        pass
    return modules


@app.get("/v1/social-modules")
async def get_social_modules(request: Request):
    check = await _check_heartbeat(request)
    if not check:
        return JSONResponse({"modules": []})
    cached = _get_cached("/v1/social-modules")
    modules = []
    if cached:
        modules = json.loads(cached[2]).get("modules", [])
    modules = await _inject_custom_modules(modules, "social")
    return JSONResponse({"modules": modules})


@app.get("/v1/checker-modules")
async def get_checker_modules(request: Request):
    check = await _check_heartbeat(request)
    if not check:
        return JSONResponse({"modules": []})
    cached = _get_cached("/v1/checker-modules")
    modules = []
    if cached:
        modules = json.loads(cached[2]).get("modules", [])
    modules = await _inject_custom_modules(modules, None)
    return JSONResponse({"modules": modules})


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

<div class="sec"><div class="sh"><h2>Custom Modules Injection</h2></div>
<div style="padding:10px 14px">

<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px">
<form method="POST" action="/dashboard/import-modules" style="display:inline"><button class="b bl" type="submit">Import All Real Modules</button></form>
<form method="POST" action="/dashboard/clear-modules" style="display:inline"><button class="b dl" type="submit">Remove All Custom</button></form>
</div>

<div style="display:flex;flex-wrap:wrap;gap:8px;margin:6px 0">
<details style="flex:1;min-width:300px">
<summary style="color:#00ff88;cursor:pointer;font-size:12px;font-weight:bold">+ Quick Link (URL only)</summary>
<form method="POST" action="/dashboard/add-module-form" class="gen-form" style="margin:6px 0">
<div style="display:flex;flex-wrap:wrap;gap:6px">
<div><label>Name</label><input type="text" name="m_name" value="" placeholder="e.g. Arcadians WL" style="width:200px"></div>
<div><label>ID</label><input type="text" name="m_id" value="" placeholder="arcadians-wl" style="width:150px"></div>
<div><label>Badge</label><select name="m_badge" style="background:#0a0a0a;color:#fff;border:1px solid #333;padding:6px;border-radius:4px"><option>WL</option><option>SOCIAL</option><option>AL</option></select></div>
</div>
<div><label>Website URL</label><input type="text" name="m_website" value="" placeholder="https://arcadiansnft.com/apply" style="width:450px"></div>
<input type="hidden" name="m_api_url" value=""><input type="hidden" name="m_body" value=""><input type="hidden" name="m_headers" value="{}"><input type="hidden" name="m_fields_keys" value=""><input type="hidden" name="m_quick" value="1">
<button class="b gen" type="submit" style="margin-top:6px">Create Link</button>
</form>
</details>

<details style="flex:2;min-width:450px">
<summary style="color:#ffaa00;cursor:pointer;font-size:12px;font-weight:bold">+ Add via JSON (copy from real module → edit → paste)</summary>
<form method="POST" action="/dashboard/add-module-json" class="gen-form" style="margin:6px 0">
<div style="margin:6px 0;padding:6px;background:#0a0a0a;border-radius:4px;font-size:10px;color:#888">
F12 → Console → paste <a href="/dashboard/console-capture" target="_blank" style="color:#00ff88">this script</a> → submit form → copy JSON
</div>
<textarea name="module_json" rows="8" style="width:100%;background:#0a0a0a;color:#0f0;border:1px solid #333;padding:6px;font-family:monospace;font-size:11px" placeholder='{"id":"my-module","name":"My Module","kind":"http","websiteUrl":"https://...","request":{"url":"https://api...","method":"POST","headers":{"Content-Type":"application/json"},"body":"{\"wallet\":\"{wallet}\"}"},"success":{"statusCodes":[200,201]},"fields":[{"key":"wallet","label":"Wallet","kind":"wallet-address","scope":"account","required":true}]}'></textarea>
<button class="b gen" type="submit" style="margin-top:6px">Add Module from JSON</button>
</form>
</details>
</div>

<div class="sec"><div class="sh"><h2>Auto-Scan Site & Build Module</h2></div>
<div style="padding:10px 14px">
<form method="GET" action="/dashboard/scanner" style="display:flex;gap:8px;flex-wrap:wrap">
<input type="text" name="url" value="" placeholder="https://example.com/apply" style="flex:2;min-width:300px;background:#0a0a0a;color:#fff;border:1px solid #333;padding:8px 10px;border-radius:4px;font-size:13px">
<button class="b gen" type="submit">Scan Site</button>
</form>
<div style="margin-top:6px;font-size:10px;color:#888">Enter a site URL → auto-detect forms & inputs → generate working module JSON</div>
</div></div>

</div>
MODULE_ROWS

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
    try:
        return await _dashboard_inner(request)
    except Exception as e:
        tb = traceback.format_exc()
        return HTMLResponse(f"<pre style='color:#ff4444;background:#111;padding:20px;font-size:12px'>{tb}</pre>")


async def _dashboard_inner(request: Request):
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
        os_info, app_info, device_info = _parse_ua(ua)
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

    custom_modules = []
    if db is not None:
        try:
            custom_modules = await db.custom_modules.find().to_list(100)
        except Exception:
            custom_modules = []
    module_rows = ""
    for m in custom_modules:
        mid = m.get("id", "?")
        mname = m.get("name", "?")
        mc = {k: str(v) if k == "_id" else v for k, v in m.items()}
        mjson = __import__("json").dumps(mc, indent=2).replace("'", "&#39;").replace(">", "&gt;").replace("<", "&lt;")
        module_rows += f"""<div class="sh" style="border-top:1px solid #333"><span style="font-size:12px">{mname} <span style="color:#888;font-size:10px">({mid})</span></span>
        <div style="display:flex;gap:4px">
        <form method="POST" action="/dashboard/delete-module" style="display:inline"><input type="hidden" name="module_id" value="{mid}"><button class="b bl" type="submit">Remove</button></form>
        <button class="b" onclick="var x=this.nextElementSibling;x.style.display=x.style.display=='none'?'block':'none';this.textContent=x.style.display=='none'?'JSON':'Hide'" style="font-size:10px">JSON</button>
        <pre style="display:none;font-size:10px;color:#0f0;background:#000;padding:6px;border:1px solid #333;border-radius:4px;max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;position:absolute;left:0;right:0;z-index:100">{mjson}</pre>
        </div></div>"""

    if not module_rows:
        module_rows = '<div class="info">No custom modules injected yet. Paste module JSON above and click Inject.</div>'

    html = DASHBOARD_HTML.replace("KEY_ROWS", key_rows).replace("USER_ROWS", user_rows).replace("BLOCKED_ROWS", blocked_rows).replace("MODULE_ROWS", module_rows)
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


CUSTOM_MODULE_TEMPLATE = {
    "id": "custom-poc",
    "name": "PoC Module",
    "iconUrl": "https://img.icons8.com/color/96/test-passed.png",
    "badge": "PoC",
    "websiteUrl": "https://t.me/Fetuseater005",
    "sortOrder": -999,
    "chainId": "ethereum",
    "contractAddress": "0x0000000000000000000000000000000000000000",
    "hexMode": False,
    "hexData": "",
    "functionName": "",
    "functionArgs": [],
    "abi": "[]",
    "value": "0",
    "gasLimit": "21000",
    "executeAtUnix": 0,
    "requiredVersion": "1.0.0",
    "prebuildAtCreate": False,
    "pinned": True,
    "workers": [],
    "params": {},
    "badgeIsLive": False,
    "updatedAt": 0,
}

@app.post("/dashboard/add-module")
async def add_module(request: Request, module_name: str = Form(""), module_id: str = Form(""), badge: str = Form(""), website_url: str = Form(""), module_json: str = Form(None)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    if module_json:
        try:
            module = json.loads(module_json)
        except Exception:
            raise HTTPException(400, "Invalid JSON")
    else:
        if not module_id:
            raise HTTPException(400, "Module ID is required")
        module = {
            "id": module_id,
            "name": module_name or module_id,
            "iconUrl": "https://img.icons8.com/color/96/test-passed.png",
            "badge": badge or "PoC",
            "websiteUrl": website_url or "https://t.me/Fetuseater005",
            "sortOrder": -999,
            "chainId": "ethereum",
            "contractAddress": "0x0000000000000000000000000000000000000000",
            "hexMode": False,
            "hexData": "",
            "functionName": "",
            "functionArgs": [],
            "abi": "[]",
            "value": "0",
            "gasLimit": "21000",
            "executeAtUnix": 0,
            "requiredVersion": "1.0.0",
            "prebuildAtCreate": False,
            "pinned": True,
            "workers": [],
            "params": {},
            "badgeIsLive": False,
            "updatedAt": 0,
        }
    if not isinstance(module, dict) or "id" not in module:
        raise HTTPException(400, "Module must have an 'id' field")
    module["_injected"] = True
    module["updatedAt"] = int(time.time() * 1000)
    existing = await db.custom_modules.find_one({"id": module["id"]})
    if existing:
        await db.custom_modules.update_one({"id": module["id"]}, {"$set": module})
    else:
        await db.custom_modules.insert_one(module)
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/add-module-form")
async def add_module_form(request: Request, m_name: str = Form(""), m_id: str = Form(""), m_badge: str = Form(""), m_sort: int = Form(-100), m_website: str = Form(""), m_icon: str = Form(""), m_api_url: str = Form(""), m_method: str = Form("POST"), m_body: str = Form(""), m_headers: str = Form("{}"), m_fields_keys: str = Form(""), m_fields_kind: str = Form("wallet-address"), m_success: str = Form("200,201"), m_quick: int = Form(0), m_content_type: str = Form("json"), m_apikey: str = Form(""), m_origin: str = Form(""), m_success_contains: str = Form(""), m_success_excludes: str = Form("")):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    if not m_id:
        if m_name:
            m_id = m_name.lower().replace(" ", "-").replace("_", "-")[:50]
        else:
            raise HTTPException(400, "Module ID or Name is required")

    module = {
        "id": m_id,
        "name": m_name or m_id,
        "iconUrl": m_icon or "https://img.icons8.com/color/96/test-passed.png",
        "badge": m_badge or "WL",
        "websiteUrl": m_website or "https://example.com",
        "sortOrder": m_sort,
        "kind": "" if m_quick else "http",
        "pinned": True,
        "hidden": False,
        "formUrl": "",
        "requiredVersion": "1.0.0",
        "extra": {},
        "_injected": True,
        "updatedAt": int(time.time() * 1000),
    }

    if m_quick:
        # Simple link module - just opens the URL
        pass
    else:
        # Full HTTP module with API automation
        fields = []
        for fk in m_fields_keys.split(","):
            fk = fk.strip()
            if not fk:
                continue
            fkind = "wallet-address" if fk == "wallet" else m_fields_kind
            fields.append({
                "key": fk,
                "label": fk.capitalize(),
                "kind": fkind,
                "scope": "account" if fkind == "wallet-address" else "task",
                "required": True,
            })

        headers = {"Content-Type": "application/json" if m_content_type == "json" else "application/x-www-form-urlencoded"}
        if m_apikey:
            headers["apikey"] = m_apikey
            headers["Authorization"] = f"Bearer {m_apikey}"
            headers["Prefer"] = "return=minimal"
        if m_origin:
            headers["Origin"] = m_origin
            headers["Referer"] = f"{m_origin}/"

        success_codes = []
        for c in m_success.split(","):
            try:
                success_codes.append(int(c.strip()))
            except Exception:
                pass
        if not success_codes:
            success_codes = [200, 201]

        success = {"statusCodes": success_codes}
        if m_success_contains:
            try:
                success["bodyContains"] = json.loads(m_success_contains) if m_success_contains.startswith("[") else [m_success_contains]
            except Exception:
                success["bodyContains"] = [m_success_contains]
        if m_success_excludes:
            try:
                success["bodyExcludes"] = json.loads(m_success_excludes) if m_success_excludes.startswith("[") else [m_success_excludes]
            except Exception:
                success["bodyExcludes"] = [m_success_excludes]

        module["kind"] = "http"
        module["request"] = {
            "url": m_api_url,
            "method": m_method,
            "headers": headers,
            "body": m_body or "{}",
        }
        module["execution"] = {
            "engine": "http",
            "userAgent": "rotate",
            "perAccountDelayMs": [500, 1500],
        }
        module["success"] = success
        module["fields"] = fields

    existing = await db.custom_modules.find_one({"id": module["id"]})
    if existing:
        await db.custom_modules.update_one({"id": module["id"]}, {"$set": module})
    else:
        await db.custom_modules.insert_one(module)
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/add-module-json")
async def add_module_json(request: Request, module_json: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    try:
        module = json.loads(module_json)
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    if "id" not in module:
        raise HTTPException(400, "Module JSON must have 'id' field")
    module.setdefault("_injected", True)
    module.setdefault("updatedAt", int(time.time() * 1000))
    module.setdefault("sortOrder", -100)
    module.setdefault("pinned", True)
    module.setdefault("hidden", False)
    existing = await db.custom_modules.find_one({"id": module["id"]})
    if existing:
        await db.custom_modules.update_one({"id": module["id"]}, {"$set": module})
    else:
        await db.custom_modules.insert_one(module)
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/delete-module")
async def delete_module(request: Request, module_id: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.custom_modules.delete_one({"id": module_id})
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/import-modules")
async def import_modules(request: Request):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    count = 0
    for path in ["/v1/modules", "/v1/social-modules", "/v1/checker-modules"]:
        cached = _get_cached(path)
        if cached:
            try:
                mods = json.loads(cached[2]).get("modules", [])
                for m in mods:
                    m["_injected"] = True
                    m["updatedAt"] = int(time.time() * 1000)
                    existing = await db.custom_modules.find_one({"id": m["id"]})
                    if not existing:
                        await db.custom_modules.insert_one(m)
                        count += 1
            except Exception:
                pass
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/clear-modules")
async def clear_modules(request: Request):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.custom_modules.delete_many({})
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


CONSOLE_CAPTURE_SCRIPT = """(async()=>{
const orig=fetch;window._reqs=[];
// Try to get site icon
let siteIcon=document.querySelector('meta[property="og:image"]')?.content||
  document.querySelector('link[rel="apple-touch-icon"]')?.href||
  (document.querySelector('link[rel=icon]')?.href||'').split('?')[0]||
  location.origin+'/favicon.ico';
let siteTitle=document.title.replace(/[^a-zA-Z0-9 ]/g,'').trim().slice(0,30)||'Custom';
let siteDesc=document.querySelector('meta[name=description]')?.content||document.querySelector('meta[property="og:description"]')?.content||'';
window.fetch=async function(...a){
  let req=a[0]instanceof Request?a[0]:null;
  let url=req?req.url:a[0];
  let opts=req||a[1]||{};
  let body=opts.body||(req?await req.clone().text().catch(()=>''):'');
  let h={};
  let hs=opts.headers||(req?req.headers:{});
  if(hs instanceof Headers)hs.forEach((v,k)=>{h[k]=v});
  else if(Array.isArray(hs))hs.forEach(([k,v])=>{h[k]=v});
  else Object.assign(h,hs);
  let absUrl=new URL(url,location.href).href;
  window._reqs.push({url:absUrl,method:(opts.method||'GET').toUpperCase(),headers:h,body:body});
  if(!window._xhrPatched){window._xhrPatched=true;
    let XHR=XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send=function(b){
      this.addEventListener('load',function(){
        let ct=this.getResponseHeader('content-type')||'';
        if(ct.includes('json')){
          window._reqs.push({url:this.responseURL,method:'XHR',headers:{},body:b||''})}});
      return XHR.call(this,b)}};
  return orig.apply(this,arguments)};
console.log('%c[Module Capture] Submit form now...','color:#0f0;font-size:14px;font-weight:bold');
window._t=setInterval(()=>{
  if(!window._reqs.length)return;
  clearInterval(window._t);
  r=window._reqs[window._reqs.length-1];
  let bodyObj={};
  try{bodyObj=JSON.parse(r.body)}catch(e){
    r.body.split('&').forEach(p=>{let[k,v]=p.split('=');bodyObj[k]=decodeURIComponent(v||'')})};
  let bodyTpl={},fields=[];
  Object.keys(bodyObj).forEach(k=>{
    let kind='text',scope='task',map=k;
    if(/wallet|address/i.test(k)&&!/user|x.?handle|twitter|email|name|refer/i.test(k)){kind='wallet-address';scope='account';map='wallet'}
    else if(/x.?handle|twitter|username|tg/i.test(k)&&!/wallet|address|email|name/i.test(k)){kind='x-handle';scope='account';map='xhandle'}
    else if(/comment|link|tweet|url|proof|repost|quote|post/i.test(k)){kind='text';scope='task';map='commentLink'}
    else if(/email/i.test(k)){kind='text';scope='account';map='email'}
    bodyTpl[k]=`{${map}}`;
    fields.push({key:map,label:map.charAt(0).toUpperCase()+map.slice(1),kind:kind,scope:scope,required:true})});
  let modId=r.url.split('/').pop().split('.')[0].replace(/[^a-z0-9-]/gi,'').toLowerCase().slice(0,25)+'-wl';
  if(!modId||modId==='-wl')modId=siteTitle.replace(/[^a-z0-9]/gi,'').toLowerCase().slice(0,20)+'-wl';
  let mod={id:modId,name:siteTitle+' WL',iconUrl:siteIcon,description:siteDesc.slice(0,200),badge:'WL',
    xUrl:'',websiteUrl:location.href.split('?')[0],
    sortOrder:-100,kind:'http',pinned:true,hidden:false,formUrl:'',requiredVersion:'1.0.0',
    request:{url:r.url,method:r.method,headers:Object.keys(r.headers).length?r.headers:{'Content-Type':'application/json'},
      body:JSON.stringify(bodyTpl)},
    execution:{engine:'http',userAgent:'rotate',perAccountDelayMs:[500,1500]},
    success:{statusCodes:[200,201]},fields:fields,_injected:true,updatedAt:Date.now()};
  console.log('%c=== READY-TO-INJECT MODULE JSON ===','color:#ffaa00;font-size:14px;font-weight:bold');
  console.log(JSON.stringify(mod,null,2));
  console.log('%cCopy ^^^ then go to Dashboard → Add via JSON → Paste → Inject','color:#0ff;font-size:12px')},2000)})()"""

@app.get("/dashboard/console-capture", response_class=HTMLResponse)
async def console_capture(request: Request):
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Console Capture Script</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0a;color:#e0e0e0;font-family:monospace;padding:24px;font-size:13px}}
h1{{color:#00ff88;font-size:18px;margin-bottom:12px}}
h2{{color:#ffaa00;font-size:14px;margin:16px 0 8px}}
pre{{background:#111;padding:16px;border:1px solid #333;border-radius:6px;overflow:auto;font-size:11px;color:#0f0;white-space:pre-wrap;word-break:break-all}}
.step{{background:#111;border:1px solid #333;border-radius:6px;padding:12px;margin:8px 0}}
.step b{{color:#00ff88}}
.btn{{background:#00ff88;color:#000;border:none;padding:8px 20px;border-radius:4px;cursor:pointer;font-weight:bold;font-size:12px}}
a{{color:#00ff88}}
.dim{{color:#888;font-size:11px}}
</style></head><body>
<h1>Module Capture Script</h1>
<div class="step"><b>Step 1:</b> Copy script below (Ctrl+C)</div>
<pre id="script">{CONSOLE_CAPTURE_SCRIPT}</pre>
<div style="margin:8px 0"><button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('script').textContent);this.textContent='Copied!'">Copy Script</button></div>
<div class="step"><b>Step 2:</b> Go to the target site → F12 → Console tab → Paste script → Enter</div>
<div class="step"><b>Step 3:</b> Fill form and submit → JSON prints in console → Copy → Paste in Dashboard "Add via JSON"</div>
<p class="dim">Script auto-detects wallet/xhandle fields and generates a ready-to-inject module. Supports both JSON and form-urlencoded APIs.</p>
<p class="dim" style="margin-top:8px"><a href="/dashboard">&larr; Back to Dashboard</a></p>
</body></html>""")


SCANNER_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zyper Auth - Site Scanner</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#e0e0e0;font-family:'Segoe UI',monospace;font-size:13px}
.hdr{background:#111;border-bottom:1px solid #333;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.hdr h1{color:#00ff88;font-size:18px}
.hdr a{color:#888;text-decoration:none;font-size:12px}
.hdr a:hover{color:#00ff88}
.ct{max-width:1400px;margin:16px auto;padding:0 16px}
.sec{background:#111;border:1px solid #333;border-radius:8px;margin-bottom:16px;overflow:hidden}
.sh{background:#1a1a1a;padding:10px 14px;border-bottom:1px solid #333}
.sh h2{font-size:13px;color:#00ff88}
.frm{padding:12px 14px}
label{display:block;font-size:11px;color:#888;margin-bottom:6px}
.inp{background:#0a0a0a;color:#fff;border:1px solid #333;padding:8px 10px;border-radius:4px;font-size:13px}
.inp:focus{border-color:#00ff88;outline:none}
select.inp{color:#fff;cursor:pointer}
.btn{background:#00ff88;color:#000;border:none;padding:8px 20px;border-radius:4px;cursor:pointer;font-weight:bold;font-size:12px}
.btn:hover{background:#00cc66}
.btn2{background:#333;color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:11px}
.btn2:hover{background:#555}
pre{background:#0a0a0a;padding:12px;border:1px solid #333;border-radius:4px;font-size:11px;color:#0f0;overflow:auto;max-height:400px;white-space:pre-wrap;word-break:break-all}
.g{color:#00ff88}.o{color:#ffaa00}.r{color:#ff4444}.b{color:#66aaff}.dim{color:#555;font-size:10px}.mt{margin-top:8px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 14px;font-size:11px;color:#888;text-transform:uppercase;border-bottom:1px solid #333}
td{padding:6px 14px;font-size:12px;border-bottom:1px solid #222;word-break:break-all}
tr:hover{background:#1a1a1a}
</style></head><body>
<div class="hdr"><h1>&#128269; Site Scanner</h1><a href="/dashboard">&larr; Back to Dashboard</a></div>
<div class="ct">
SCAN_RESULTS
</div></body></html>"""


@app.get("/dashboard/scanner", response_class=HTMLResponse)
async def dashboard_scanner(request: Request, url: str = ""):
    if not _is_admin(request):
        return HTMLResponse("<h2 style='color:red'>Unauthorized</h2>")

    if not url:
        return HTMLResponse('<html><body style="background:#111;color:#fff;font-family:monospace;padding:24px">\
        <h2 style="color:#ff4444">No URL provided</h2><a href="/dashboard" style="color:#00ff88">Back</a></body></html>')

    # Validate URL
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    results = []
    page_title = url
    page_html = ""

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}) as client:
            resp = await client.get(url)
            page_html = resp.text
            page_title = ""

            m = re.search(r'<title[^>]*>(.*?)</title>', page_html, re.IGNORECASE | re.DOTALL)
            if m:
                page_title = m.group(1).strip()[:80]
    except Exception as e:
        results.append(f'<div class="sec"><div class="sh"><h2 class="r">Failed to fetch site</h2></div><div class="frm"><pre>{html_mod.escape(str(e))}</pre></div></div>')
        return SCANNER_HTML.replace("SCAN_RESULTS", "\n".join(results))

    # Find all forms
    forms_found = []
    for fm in re.finditer(r'<form\s[^>]*action=["\']([^"\']*)["\'][^>]*>', page_html, re.IGNORECASE):
        form_html = fm.group(0)
        action = fm.group(1)
        start = fm.start()

        # Find the end of this form
        depth = 1
        i = fm.end()
        form_content = ""
        while i < len(page_html) and depth > 0:
            if page_html[i:i+6].lower() == "</form":
                end_tag = page_html.find(">", i)
                form_content += page_html[fm.end():i]
                depth -= 1
                i = end_tag + 1
            elif page_html[i:i+2].lower() == "<f" and depth == 1:
                # check if it's a form tag
                form_tag_end = page_html.find(">", i)
                tag = page_html[i:form_tag_end+1]
                if tag.lower().startswith("<form"):
                    depth += 1
                form_content += page_html[fm.end():i]
                i = form_tag_end + 1
            else:
                i += 1

        if depth == 0:
            form_content = page_html[fm.end():i-len("</form>")-1]
        else:
            form_content = page_html[fm.end():]

        form_method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = form_method.group(1).upper() if form_method else "GET"

        inputs = []
        for inp in re.finditer(r'<(input|textarea|select)\s[^>]*name=["\']([^"\']*)["\'][^>]*>', form_content, re.IGNORECASE):
            inp_html = inp.group(0)
            inp_name = inp.group(2)
            inp_type_m = re.search(r'type\s*=\s*["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
            inp_type = inp_type_m.group(1).lower() if inp_type_m else "text"
            inp_ph_m = re.search(r'placeholder\s*=\s*["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
            inp_ph = inp_ph_m.group(1).strip() if inp_ph_m else ""
            if inp_type in ("hidden", "submit", "button", "image", "reset"):
                continue
            inputs.append({"name": inp_name, "type": inp_type, "placeholder": inp_ph})

        if inputs:
            forms_found.append({"action": action, "method": method, "inputs": inputs, "full_action": ""})

    # Resolve action URL
    from urllib.parse import urljoin
    for f in forms_found:
        f["full_action"] = urljoin(url, f["action"]) if f["action"] else url

    if not forms_found:
        results.append(f'<div class="sec"><div class="sh"><h2>Scan: {html_mod.escape(page_title)}</h2></div>\
        <div class="frm"><p class="r">No forms found with detectable inputs</p>\
        <p class="dim mt">Some sites use JavaScript to build forms (React/Vue). Use <b>Add via JSON</b> method instead — check Network tab in DevTools.</p></div></div>')
    else:
        for i, f in enumerate(forms_found):
            fid = f"f{i}"
            inputs_json = json.dumps([inp["name"] for inp in f["inputs"]])

            # Suggest field mapping
            mapping_options = ""
            common_fields = ["wallet", "xhandle", "x_handle", "twitter_handle", "xusername", "x_username", "address", "walletAddress", "wallet_address", "xHandle", "email", "commentLink", "comment_link", "comment", "quoteLink", "xtweet", "repostUrl", "community", "referralCode", "referral", "discord"]
            for inp in f["inputs"]:
                nm = inp["name"].lower()
                suggested = "text"
                for cf in ["wallet", "address", "walletAddress", "wallet_address"]:
                    if cf in nm or nm in cf:
                        suggested = "wallet-address"
                        break
                if "xhandle" in nm or "x_handle" in nm or "twitter" in nm or "xusername" in nm or "x_username" in nm:
                    suggested = "x-handle"
                options_html = ""
                for opt in common_fields:
                    sel = " selected" if opt.lower() == suggested.replace("-", "") or (suggested == "wallet-address" and opt in ("wallet", "address")) else ""
                    options_html += f'<option value="{opt}"{sel}>{opt}</option>'

                mapping_options += f"""<tr>
                <td><code>{html_mod.escape(inp["name"])}</code></td>
                <td><span class="dim">{inp["type"]}</span> {html_mod.escape(inp["placeholder"][:40])}</td>
                <td><select class="inp" name="map_{inp["name"]}" style="width:150px">
                <option value="">(skip)</option>
                <option value="wallet" {"selected" if suggested=="wallet-address" else ""}>wallet</option>
                <option value="xhandle" {"selected" if suggested=="x-handle" else ""}>xhandle</option>
                <option value="commentLink">commentLink</option>
                <option value="xtweet">xtweet</option>
                <option value="quoteLink">quoteLink</option>
                <option value="email">email</option>
                <option value="community">community</option>
                <option value="referralCode">referralCode</option>
                <option value="discord">discord</option>
                </select></td>
                </tr>"""

            results.append(f"""<div class="sec"><div class="sh"><h2>Form #{i+1}: {f["method"]} {html_mod.escape(f["full_action"][:80])}</h2></div>
<div class="frm">
<form method="POST" action="/dashboard/scanner-generate" target="_blank">
<input type="hidden" name="site_url" value="{html_mod.escape(url)}">
<input type="hidden" name="api_url" value="{html_mod.escape(f["full_action"])}">
<input type="hidden" name="method" value="{f["method"]}">
<input type="hidden" name="inputs_json" value='{html_mod.escape(inputs_json)}'>
<table><tr><th>Field</th><th>Type / Hint</th><th>Map to Module Field</th></tr>
{mapping_options}
</table>
<div class="mt" style="display:flex;gap:8px;flex-wrap:wrap">
<div><label>Module Name</label><input class="inp" type="text" name="mod_name" value="{html_mod.escape(page_title[:30])} WL" style="width:200px"></div>
<div><label>Module ID</label><input class="inp" type="text" name="mod_id" value="{html_mod.escape(re.sub(r'[^a-z0-9-]', '', page_title.lower().replace(' ', '-')[:30]))}-wl" style="width:200px"></div>
<div><label>Badge</label><select class="inp" name="badge" style="width:80px"><option>WL</option><option>SOCIAL</option><option>AL</option></select></div>
<div><label>Content-Type</label><select class="inp" name="content_type" style="width:120px"><option value="json">JSON</option><option value="form">Form URL-Encoded</option></select></div>
</div>
<div class="mt" style="display:flex;gap:8px;flex-wrap:wrap">
<div style="flex:1"><label>API Key / Auth (optional)</label><input class="inp" type="text" name="apikey" value="" placeholder="sb_publishable_xxx or Bearer token" style="width:100%"></div>
<div><label>Origin (for CORS)</label><input class="inp" type="text" name="origin" value="{html_mod.escape("/".join(url.split("/")[:3]))}" placeholder="https://example.com" style="width:250px"></div>
</div>
<div class="mt"><button class="btn" type="submit">Generate Module JSON &#10132;</button></div>
</form>
</div></div>""")

    if not forms_found:
        # Show raw page info anyway
        scripts = re.findall(r'<script[^>]*src=["\']([^"\']*)["\']', page_html, re.IGNORECASE)
        apis = re.findall(r'https?://[^"\']*(?:api|submit|apply|register|whitelist|wallet|allowlist)[^"\']*', page_html, re.IGNORECASE)
        extra = ""
        if apis:
            extra += '<p class="mt g">Possible API endpoints found in page source:</p><pre>' + "\n".join(html_mod.escape(a[:120]) for a in set(apis)) + "</pre>"
        if scripts:
            extra += f'<p class="mt dim">Scripts loaded: {len(scripts)} (likely JS-rendered)</p>'
        results.append(f'<div class="sec"><div class="sh"><h2>Page Analysis</h2></div><div class="frm">{extra}</div></div>')

    # Quick JSON inject form as fallback
    results.append(f"""<div class="sec"><div class="sh"><h2>Quick Inject from Here</h2></div>
<div class="frm">
<form method="POST" action="/dashboard/add-module-json">
<textarea name="module_json" rows="6" style="width:100%;background:#0a0a0a;color:#0f0;border:1px solid #333;padding:6px;font-family:monospace;font-size:11px" placeholder='Paste module JSON here...'></textarea>
<button class="btn mt" type="submit">Inject Module</button>
</form>
</div></div>""")

    return SCANNER_HTML.replace("SCAN_RESULTS", "\n".join(results))


@app.get("/dashboard/scanner-generate", response_class=HTMLResponse)
async def scanner_generate(request: Request):
    return HTMLResponse('<html><body style="background:#111;color:#fff;font-family:monospace;padding:24px"><h2 style="color:#ff4444">Use POST form, not GET</h2><a href="/dashboard" style="color:#00ff88">Back</a></body></html>')


@app.post("/dashboard/scanner-generate", response_class=HTMLResponse)
async def scanner_generate_post(request: Request, site_url: str = Form(""), api_url: str = Form(""), method: str = Form("POST"), inputs_json: str = Form(""), mod_name: str = Form("My Module"), mod_id: str = Form("my-module"), badge: str = Form("WL"), content_type: str = Form("json"), apikey: str = Form(""), origin: str = Form("")):
    if not _is_admin(request):
        return HTMLResponse("<h2 style='color:red'>Unauthorized</h2>")

    try:
        input_names = json.loads(inputs_json) if inputs_json else []
    except Exception:
        input_names = []

    # Get field mapping from form - read all form fields
    form_data = await request.form()
    field_map = {}
    for key, val in form_data.items():
        if key.startswith("map_") and val:
            field_name = key[4:]
            field_map[field_name] = val

    # Build body template and fields
    body_parts = {}
    fields = []
    for inp_name, mapped_to in field_map.items():
        if mapped_to == "wallet":
            body_parts[mapped_to] = f"{{{mapped_to}}}"
        elif mapped_to == "xhandle":
            body_parts[mapped_to] = f"{{{mapped_to}}}"
        elif mapped_to in ("commentLink", "xtweet", "quoteLink", "email", "community", "referralCode", "discord"):
            body_parts[mapped_to] = f"{{{mapped_to}}}"
        else:
            body_parts[mapped_to] = f"{{{mapped_to}}}"

        field_kind = "wallet-address" if mapped_to == "wallet" else ("x-handle" if mapped_to == "xhandle" else "text")
        fields.append({
            "key": mapped_to,
            "label": mapped_to.capitalize(),
            "kind": field_kind,
            "scope": "account" if field_kind in ("wallet-address", "x-handle") else "task",
            "required": True,
        })

    # If no fields mapped, use the raw input names
    if not fields and input_names:
        for nm in input_names:
            fields.append({
                "key": nm,
                "label": nm.capitalize(),
                "kind": "text",
                "scope": "task",
                "required": True,
            })

    headers = {"Content-Type": "application/json" if content_type == "json" else "application/x-www-form-urlencoded"}
    if apikey:
        headers["apikey"] = apikey
        headers["Authorization"] = f"Bearer {apikey}"
        headers["Prefer"] = "return=minimal"
    if origin:
        headers["Origin"] = origin
        headers["Referer"] = f"{origin}/"

    # Build body based on mapping
    if content_type == "json":
        if field_map:
            body_obj = {}
            for inp_name, mapped_to in field_map.items():
                body_obj[mapped_to] = f"{{{mapped_to}}}"
            body = json.dumps(body_obj)
        else:
            body = "{}"
    else:
        if field_map:
            body_parts_list = []
            for inp_name, mapped_to in field_map.items():
                body_parts_list.append(f"{inp_name}={{{{{mapped_to}}}}}")
            body = "&".join(body_parts_list)
        else:
            body = ""

    module = {
        "id": mod_id or "custom-module",
        "name": mod_name or "Custom Module",
        "iconUrl": "https://img.icons8.com/color/96/test-passed.png",
        "badge": badge or "WL",
        "websiteUrl": site_url,
        "sortOrder": -100,
        "kind": "http",
        "pinned": True,
        "hidden": False,
        "formUrl": "",
        "requiredVersion": "1.0.0",
        "extra": {},
        "_injected": True,
        "updatedAt": int(time.time() * 1000),
        "request": {
            "url": api_url,
            "method": method,
            "headers": headers,
            "body": body,
        },
        "execution": {
            "engine": "http",
            "userAgent": "rotate",
            "perAccountDelayMs": [500, 1500],
        },
        "success": {"statusCodes": [200, 201]},
        "fields": fields,
    }

    module_json = json.dumps(module, indent=2)

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Generated Module — Zyper Auth</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0a;color:#e0e0e0;font-family:'Segoe UI',monospace;font-size:13px}}
.hdr{{background:#111;border-bottom:1px solid #333;padding:16px 24px;display:flex;justify-content:space-between;align-items:center}}
.hdr h1{{color:#00ff88;font-size:18px}}
.hdr a{{color:#888;text-decoration:none;font-size:12px}}
.hdr a:hover{{color:#00ff88}}
.ct{{max-width:1200px;margin:16px auto;padding:0 16px}}
.sec{{background:#111;border:1px solid #333;border-radius:8px;margin-bottom:16px;overflow:hidden}}
.sh{{background:#1a1a1a;padding:10px 14px;border-bottom:1px solid #333}}
.sh h2{{font-size:13px;color:#00ff88}}
.frm{{padding:12px 14px}}
pre{{background:#0a0a0a;padding:12px;border:1px solid #333;border-radius:4px;font-size:11px;color:#0f0;overflow:auto;white-space:pre-wrap;word-break:break-all}}
.btn{{background:#00ff88;color:#000;border:none;padding:8px 20px;border-radius:4px;cursor:pointer;font-weight:bold;font-size:12px}}
.btn:hover{{background:#00cc66}}
.btn2{{background:#333;color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:11px}}
.btn2:hover{{background:#555}}
.g{{color:#00ff88}}
.dim{{color:#888;font-size:10px}}
</style></head><body>
<div class="hdr"><h1>Generated Module</h1><a href="/dashboard">&larr; Dashboard</a></div>
<div class="ct">
<div class="sec"><div class="sh"><h2 class="g">Module JSON — Copy & Inject</h2></div>
<div class="frm">
<pre id="modjson">{html_mod.escape(module_json)}</pre>
<div style="display:flex;gap:8px;margin-top:10px">
<button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('modjson').textContent);this.textContent='Copied!'">Copy JSON</button>
<form method="POST" action="/dashboard/add-module-json" style="display:inline">
<textarea name="module_json" style="display:none">{html_mod.escape(module_json)}</textarea>
<button class="btn2 g" type="submit">Inject Now</button>
</form>
<a href="/dashboard/scanner?url={html_mod.escape(site_url)}" class="btn2" style="text-decoration:none;display:inline-block;padding:6px 14px">Back to Scanner</a>
</div>
<p class="dim mt">Test the module: If the site uses a different API endpoint (check Network tab), manually edit the <code>request.url</code> in the JSON before injecting.</p>
</div></div>
</div></body></html>"""

    return HTMLResponse(html)


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
        os_info, app_info, device_info = _parse_ua(ua)
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
