import os
import json
import time
import uuid
import secrets
import threading
import httpx
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, client
    if MONGO_URI:
        client = AsyncIOMotorClient(MONGO_URI)
        db = client.zyper_auth
        await db.keys.create_index("key", unique=True)
        await db.keys.create_index("hwid")
        await db.sessions.create_index("hwid")
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

    if not req_hwid:
        return JSONResponse({"ok": False, "state": "invalid", "error": "no hwid"})

    if db is None:
        return JSONResponse({"ok": False, "state": "invalid", "error": "no database"})

    if kill_switch:
        return JSONResponse({"ok": False, "state": "invalid", "error": "system offline"})

    if req_key:
        key_doc = await db.keys.find_one({"key": req_key})
        if not key_doc:
            return JSONResponse({"ok": False, "state": "invalid", "error": "invalid key"})

        if key_doc.get("disabled"):
            return JSONResponse({"ok": False, "state": "invalid", "error": "key revoked"})

        if key_doc.get("expires_at") and datetime.utcnow() > key_doc["expires_at"]:
            return JSONResponse({"ok": False, "state": "invalid", "error": "key expired"})

        existing_session = await db.sessions.find_one({"hwid": req_hwid})
        if existing_session and not existing_session.get("active", True):
            return JSONResponse({"ok": False, "state": "invalid", "error": "device kicked by admin"})

        max_devices = key_doc.get("max_devices", 1)
        bound_hwids = await db.sessions.distinct("hwid", {"bound_key": req_key, "active": True})
        if req_hwid not in bound_hwids and len(bound_hwids) >= max_devices:
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
            return JSONResponse({"ok": False, "state": "invalid", "error": "device kicked by admin"})

        bound_key = await db.keys.find_one({"key": session["bound_key"]})
        if bound_key and not bound_key.get("disabled"):
            if bound_key.get("expires_at") and datetime.utcnow() > bound_key["expires_at"]:
                return JSONResponse({"ok": False, "state": "invalid", "error": "key expired"})

            await db.sessions.update_one(
                {"hwid": req_hwid},
                {"$set": {"last_seen": datetime.utcnow(), "ip": client_ip, "user_agent": user_agent}}
            )

            return JSONResponse({
                "ok": True,
                "state": "valid",
                "hwid": req_hwid,
                "hasKey": True,
                "key": session["bound_key"],
                "expires_at": bound_key["expires_at"].isoformat() if bound_key.get("expires_at") else None,
            })

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

    if not req_hwid:
        return JSONResponse({"ok": False, "error": "no hwid"})

    if db is None:
        return JSONResponse({"ok": False, "error": "no database"})

    if kill_switch:
        return JSONResponse({"ok": False, "error": "system offline"})

    if not req_key:
        return JSONResponse({"ok": False, "state": "pending", "error": "enter license key"})

    key_doc = await db.keys.find_one({"key": req_key})
    if not key_doc:
        return JSONResponse({"ok": False, "state": "invalid", "error": "invalid key"})

    if key_doc.get("disabled"):
        return JSONResponse({"ok": False, "state": "invalid", "error": "key revoked"})

    if key_doc.get("expires_at") and datetime.utcnow() > key_doc["expires_at"]:
        return JSONResponse({"ok": False, "state": "invalid", "error": "key expired"})

    max_devices = key_doc.get("max_devices", 1)
    bound_hwids = await db.sessions.distinct("hwid", {"bound_key": req_key})
    if req_hwid not in bound_hwids and len(bound_hwids) >= max_devices:
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
.b{padding:6px 14px;border:none;border-radius:4px;font-size:11px;cursor:pointer;font-weight:bold;text-decoration:none;display:inline-block}
.b.gen{background:#00ff88;color:#000}
.b.dl{background:#333;color:#fff}
.b.bl{background:#ff4444;color:#fff}
.b.grn{background:#00ff88;color:#000}
.b:hover{opacity:.85}
.gen-form{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 14px}
.gen-form input,.gen-form select{background:#0a0a0a;color:#fff;border:1px solid #333;padding:6px 10px;border-radius:4px;font-size:12px}
.gen-form label{font-size:11px;color:#888}
.kc{font-family:monospace;color:#00ff88;letter-spacing:1px}
.ts{font-size:10px;color:#666}
.on{color:#00ff88}.off{color:#ff4444}
.info{font-size:10px;color:#555;padding:4px 14px}
</style></head><body>
<div class="hdr"><h1>Zyper Auth Dashboard</h1>
<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
<div class="stats">
<div class="st"><div class="n">TOTAL</div><div class="l">keys</div></div>
<div class="st"><div class="n" style="color:#00ff88">ACTIVE</div><div class="l">users</div></div>
<div class="st"><div class="n" style="color:#ffaa00">KEYS</div><div class="l">generated</div></div>
</div>
<form method="POST" action="/dashboard/refresh" style="display:inline"><button class="b gen" type="submit">Refresh Modules</button></form>
<form method="POST" action="/dashboard/killswitch" style="display:inline"><button class="b KS_CLASS" type="submit">KS_LABEL</button></form>
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

<div class="sec"><div class="sh"><h2>Active Users</h2></div>
<table><tr><th>HWID</th><th>Key</th><th>IP</th><th>User Agent</th><th>First Seen</th><th>Last Seen</th><th>Note</th><th>Actions</th></tr>
USER_ROWS
</table></div>

<div class="sec"><div class="sh"><h2>All Keys</h2></div>
<table><tr><th>Key</th><th>Status</th><th>Devices</th><th>Expires</th><th>Note</th><th>Created</th><th>Actions</th></tr>
KEY_ROWS
</table></div>

</div>
<script>setTimeout(()=>location.reload(),15000)</script>
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
    active_users = sum(1 for s in sessions if s.get("active"))

    key_rows = ""
    for k in keys:
        status = "disabled" if k.get("disabled") else ("expired" if k.get("expires_at") and datetime.utcnow() > k["expires_at"] else "active")
        exp = k["expires_at"].strftime("%d %b %Y %H:%M") if k.get("expires_at") else "never"
        created = k["created_at"].strftime("%d %b %Y %H:%M") if k.get("created_at") else "-"
        note = k.get("note", "") or "-"
        maxd = k.get("max_devices", 1)
        key_rows += f"""<tr><td class="kc">{k['key']}</td>
        <td><span class="s {status}">{status}</span></td>
        <td>{maxd}</td><td style="font-size:10px">{exp}</td>
        <td style="font-size:10px">{note}</td><td class="ts">{created}</td>
        <td>
        <form method="POST" action="/dashboard/toggle-key" style="display:inline"><input type="hidden" name="key" value="{k['key']}"><button class="b {'bl' if status=='active' else 'grn'}" type="submit">{'Revoke' if status=='active' else 'Enable'}</button></form>
        <form method="POST" action="/dashboard/delete-key" style="display:inline"><input type="hidden" name="key" value="{k['key']}"><button class="b dl" type="submit">Del</button></form>
        </td></tr>"""

    if not key_rows:
        key_rows = '<tr><td colspan="7" style="text-align:center;color:#555;padding:16px">No keys generated yet</td></tr>'

    user_rows = ""
    for s in sessions:
        if not s.get("active"):
            continue
        hwid = s.get("hwid", "-")[:20] + "..."
        key = s.get("bound_key", "-")
        ip = s.get("ip", "-")
        ua = s.get("user_agent", "-")
        if len(ua) > 50:
            ua = ua[:50] + "..."
        first = s["first_seen"].strftime("%d %b %H:%M") if s.get("first_seen") else "-"
        last = s["last_seen"].strftime("%d %b %H:%M") if s.get("last_seen") else "-"
        key_note = ""
        if key and key != "-":
            kd = await db.keys.find_one({"key": key})
            key_note = kd.get("note", "") if kd else ""
        user_rows += f"""<tr>
        <td style="font-size:10px;word-break:break-all">{hwid}</td>
        <td class="kc" style="font-size:10px">{key}</td>
        <td>{ip}</td>
        <td style="font-size:9px;max-width:200px;overflow:hidden;text-overflow:ellipsis">{ua}</td>
        <td class="ts">{first}</td><td class="ts">{last}</td>
        <td style="font-size:10px">{key_note or '-'}</td>
        <td>
        <form method="POST" action="/dashboard/kick" style="display:inline"><input type="hidden" name="hwid" value="{s.get('hwid','')}"><button class="b bl" type="submit">Kick</button></form>
        <form method="POST" action="/dashboard/unkick" style="display:inline"><input type="hidden" name="hwid" value="{s.get('hwid','')}"><button class="b grn" type="submit">Unkick</button></form>
        </td></tr>"""

    if not user_rows:
        user_rows = '<tr><td colspan="8" style="text-align:center;color:#555;padding:16px">No active users</td></tr>'

    html = DASHBOARD_HTML.replace("KEY_ROWS", key_rows).replace("USER_ROWS", user_rows)
    html = html.replace("TOTAL", str(total_keys)).replace("ACTIVE", str(active_users)).replace("KEYS", str(total_keys))
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
    await db.sessions.update_many({"bound_key": key}, {"$set": {"active": False, "bound_key": ""}})
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/kick")
async def kick_user(request: Request, hwid: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.sessions.update_one({"hwid": hwid}, {"$set": {"active": False}})
    return RedirectResponse(url="/dashboard", status_code=302)


@app.post("/dashboard/unkick")
async def unkick_user(request: Request, hwid: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.sessions.update_one({"hwid": hwid}, {"$set": {"active": True}})
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


@app.post("/dashboard/refresh")
async def refresh_cache(request: Request):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    for path in ENDPOINTS:
        _fetch_endpoint(path)
    return RedirectResponse(url="/dashboard", status_code=302)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
