import os
import json
import ssl
import time
import threading
import urllib.request
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from pydantic import BaseModel
from typing import Optional

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

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def _fetch_endpoint(path, method="GET"):
    try:
        url = REAL_BASE + path
        req = urllib.request.Request(url, method=method)
        req.add_header("Accept-Encoding", "identity")
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = resp.read()
            with _cache_lock:
                _cache[path] = (resp.status, dict(resp.headers), data)
            return True
    except Exception:
        return False


def _refresh_cache_loop():
    while True:
        for path, method in ENDPOINTS.items():
            _fetch_endpoint(path, method)
        time.sleep(120)


def _get_cached(path):
    with _cache_lock:
        return _cache.get(path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, client
    if MONGO_URI:
        client = AsyncIOMotorClient(MONGO_URI)
        db = client.zyper_auth
        await db.devices.create_index("hwid", unique=True)
    bg = threading.Thread(target=_refresh_cache_loop, daemon=True)
    bg.start()
    for path, method in ENDPOINTS.items():
        _fetch_endpoint(path, method)
    yield
    if client:
        client.close()


app = FastAPI(title="Zyper Auth Server", lifespan=lifespan)


def _is_admin(request: Request):
    token = request.cookies.get("admin_token")
    if token == ADMIN_PASSWORD:
        return True
    pw = request.query_params.get("pw")
    if pw == ADMIN_PASSWORD:
        return True
    return False


DASHBOARD_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zyper Auth Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#e0e0e0;font-family:monospace;min-height:100vh}
.hdr{background:#111;border-bottom:1px solid #333;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}
.hdr h1{color:#00ff88;font-size:18px}
.stats{display:flex;gap:12px}
.st{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:8px 14px;text-align:center}
.st .n{font-size:22px;font-weight:bold;color:#00ff88}
.st .l{font-size:10px;color:#888;text-transform:uppercase}
.ct{max-width:1200px;margin:16px auto;padding:0 16px}
.sec{background:#111;border:1px solid #333;border-radius:8px;margin-bottom:16px;overflow:hidden}
.sh{background:#1a1a1a;padding:10px 14px;border-bottom:1px solid #333;display:flex;justify-content:space-between;align-items:center}
.sh h2{font-size:13px;color:#00ff88}
.bg{background:#00ff88;color:#000;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 14px;font-size:11px;color:#888;text-transform:uppercase;border-bottom:1px solid #333}
td{padding:8px 14px;font-size:12px;border-bottom:1px solid #222}
tr:hover{background:#1a1a1a}
.s{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:bold;text-transform:uppercase}
.s.pending{background:#332200;color:#ffaa00}
.s.approved{background:#003322;color:#00ff88}
.s.blocked{background:#330000;color:#ff4444}
.ac{display:flex;gap:4px;flex-wrap:wrap}
.b{padding:4px 10px;border:none;border-radius:4px;font-size:10px;cursor:pointer;font-weight:bold;text-decoration:none}
.b.ap{background:#00ff88;color:#000}
.b.bl{background:#ff4444;color:#fff}
.b.ex{background:#ffaa00;color:#000}
.b.dl{background:#333;color:#fff}
.b:hover{opacity:.85}
.af{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.af input,.af select{background:#0a0a0a;color:#fff;border:1px solid #333;padding:6px 10px;border-radius:4px;font-size:12px}
.cd{color:#ffaa00;font-weight:bold}
.ex{color:#ff4444}
</style></head><body>
<div class="hdr"><h1>Zyper Auth Dashboard</h1>
<div class="stats">
<div class="st"><div class="n">TOTAL</div><div class="l">devices</div></div>
<div class="st"><div class="n" style="color:#ffaa00">PENDING</div><div class="l">requests</div></div>
<div class="st"><div class="n" style="color:#00ff88">ACTIVE</div><div class="l">devices</div></div>
</div></div>
<div class="ct">
<div class="sec"><div class="sh"><h2>Pending Requests</h2></div>
<table><tr><th>HWID</th><th>Name</th><th>Requested</th><th>Action</th></tr>
PENDING_ROWS
</table></div>
<div class="sec"><div class="sh"><h2>All Devices</h2></div>
<table><tr><th>HWID</th><th>Name</th><th>Status</th><th>Expires</th><th>Remaining</th><th>Actions</th></tr>
DEVICE_ROWS
</table></div>
</div>
<script>setTimeout(()=>location.reload(),15000)</script>
</body></html>"""


@app.post("/v1/license/validate")
async def license_validate(request: Request):
    body = await request.body()
    req_hwid = ""
    if body:
        try:
            data = json.loads(body)
            req_hwid = data.get("hwid", "")
        except:
            pass

    if not req_hwid:
        return JSONResponse({"ok": False, "state": "invalid", "error": "no hwid"})
    if db is None:
        return JSONResponse({"ok": False, "state": "invalid", "error": "no database"})

    device = await db.devices.find_one({"hwid": req_hwid})

    if not device:
        await db.devices.insert_one({
            "hwid": req_hwid, "name": "", "status": "pending",
            "created_at": datetime.utcnow(), "approved_at": None, "expires_at": None,
        })
        return JSONResponse({"ok": False, "state": "pending", "error": "waiting for approval"})

    if device["status"] == "pending":
        return JSONResponse({"ok": False, "state": "pending", "error": "waiting for approval"})
    if device["status"] == "blocked":
        return JSONResponse({"ok": False, "state": "blocked", "error": "device blocked"})
    if device["expires_at"] and datetime.utcnow() > device["expires_at"]:
        return JSONResponse({"ok": False, "state": "expired", "error": "access expired"})

    remaining = None
    if device["expires_at"]:
        remaining = (device["expires_at"] - datetime.utcnow()).total_seconds()

    return JSONResponse({
        "ok": True, "state": "valid", "hwid": req_hwid, "hasKey": True,
        "expires_at": device["expires_at"].isoformat() if device["expires_at"] else None,
        "remaining_seconds": int(remaining) if remaining else None,
    })


@app.post("/v1/license/activate")
async def license_activate(request: Request):
    body = await request.body()
    req_hwid = ""
    if body:
        try:
            data = json.loads(body)
            req_hwid = data.get("hwid", "")
        except:
            pass
    if not req_hwid:
        return JSONResponse({"ok": False, "error": "no hwid"})
    if db is None:
        return JSONResponse({"ok": False, "error": "no database"})
    device = await db.devices.find_one({"hwid": req_hwid})
    if not device:
        await db.devices.insert_one({
            "hwid": req_hwid, "name": "", "status": "pending",
            "created_at": datetime.utcnow(), "approved_at": None, "expires_at": None,
        })
    return JSONResponse({"ok": True, "state": "pending"})


@app.get("/v1/modules")
async def get_modules():
    cached = _get_cached("/v1/modules")
    if cached:
        return JSONResponse(json.loads(cached[2]))
    return JSONResponse({"modules": []})


@app.get("/v1/social-modules")
async def get_social_modules():
    cached = _get_cached("/v1/social-modules")
    if cached:
        return JSONResponse(json.loads(cached[2]))
    return JSONResponse({"modules": []})


@app.get("/v1/checker-modules")
async def get_checker_modules():
    cached = _get_cached("/v1/checker-modules")
    if cached:
        return JSONResponse(json.loads(cached[2]))
    return JSONResponse({"modules": []})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not _is_admin(request):
        return HTMLResponse("""<html><head><title>Zyper Auth</title>
<style>body{background:#0a0a0a;color:#fff;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.l{background:#111;padding:40px;border:1px solid #333;border-radius:8px;text-align:center}
input{background:#1a1a1a;color:#fff;border:1px solid #333;padding:12px;font-size:16px;border-radius:4px;width:250px}
button{background:#00ff88;color:#000;border:none;padding:12px 30px;font-size:16px;border-radius:4px;cursor:pointer;margin-top:10px;font-weight:bold}</style></head>
<body><div class="l"><h2>Zyper Auth</h2><br>
<form method="GET" action="/dashboard"><input type="password" name="pw" placeholder="Password" autofocus><br><br>
<button type="submit">Login</button></form></div></body></html>""")

    if db is None:
        return HTMLResponse("<h1 style='color:red'>Database not connected</h1>")

    devices = await db.devices.find().sort("created_at", -1).to_list(100)

    pending_rows = ""
    device_rows = ""
    pending_count = 0
    active_count = 0

    for d in devices:
        remaining = None
        if d.get("expires_at"):
            rem = (d["expires_at"] - datetime.utcnow()).total_seconds()
            remaining = max(0, int(rem))

        hwid = d["hwid"]
        name = d.get("name", "") or "-"
        status = d["status"]
        created = d["created_at"].strftime("%d %b %H:%M") if d.get("created_at") else "-"
        exp = d["expires_at"].strftime("%d %b %H:%M") if d.get("expires_at") else "N/A"

        if remaining:
            rem_h = round(remaining / 3600, 1)
            if rem_h > 24:
                rem_str = f'<span class="cd">{round(rem_h/24,1)}d</span>'
            elif rem_h > 0:
                rem_str = f'<span class="cd">{rem_h}h</span>'
            else:
                rem_str = '<span class="ex">EXPIRED</span>'
        else:
            rem_str = "-"

        if status == "pending":
            pending_count += 1
            pending_rows += f"""<tr><td style="font-size:10px;word-break:break-all">{hwid}</td><td>{name}</td><td>{created}</td><td>
            <form method="POST" action="/dashboard/approve?pw={ADMIN_PASSWORD}" style="display:inline">
            <input type="hidden" name="hwid" value="{hwid}">
            <input type="number" name="days" value="7" min="1" max="365" style="width:45px">
            <input type="text" name="name" placeholder="name" style="width:70px">
            <button class="b ap" type="submit">Approve</button></form>
            <form method="POST" action="/dashboard/block?pw={ADMIN_PASSWORD}" style="display:inline">
            <input type="hidden" name="hwid" value="{hwid}">
            <button class="b bl" type="submit">Block</button></form></td></tr>"""
        else:
            if status == "approved":
                active_count += 1
            actions = ""
            if status == "approved":
                actions += f"""<form method="POST" action="/dashboard/extend?pw={ADMIN_PASSWORD}" style="display:inline">
                <input type="hidden" name="hwid" value="{hwid}">
                <input type="number" name="days" value="7" min="1" style="width:40px">
                <button class="b ex" type="submit">+Days</button></form>"""
            actions += f"""<form method="POST" action="/dashboard/delete?pw={ADMIN_PASSWORD}" style="display:inline">
            <input type="hidden" name="hwid" value="{hwid}">
            <button class="b dl" type="submit">Del</button></form>"""
            device_rows += f"""<tr><td style="font-size:10px;word-break:break-all">{hwid}</td><td>{name}</td>
            <td><span class="s {status}">{status}</span></td><td style="font-size:10px">{exp}</td>
            <td>{rem_str}</td><td><div class="ac">{actions}</div></td></tr>"""

    if not pending_rows:
        pending_rows = '<tr><td colspan="4" style="text-align:center;color:#555;padding:16px">No pending requests</td></tr>'
    if not device_rows:
        device_rows = '<tr><td colspan="6" style="text-align:center;color:#555;padding:16px">No devices yet</td></tr>'

    html = DASHBOARD_HTML.replace("PENDING_ROWS", pending_rows).replace("DEVICE_ROWS", device_rows)
    html = html.replace("TOTAL", str(len(devices))).replace("PENDING", str(pending_count)).replace("ACTIVE", str(active_count))
    return HTMLResponse(html)


@app.post("/dashboard/approve")
async def approve_device(request: Request, hwid: str = Form(...), days: int = Form(7), name: str = Form("")):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    expires = datetime.utcnow() + timedelta(days=days)
    await db.devices.update_one({"hwid": hwid}, {"$set": {"status": "approved", "name": name, "approved_at": datetime.utcnow(), "expires_at": expires}})
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


@app.post("/dashboard/block")
async def block_device(request: Request, hwid: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.devices.update_one({"hwid": hwid}, {"$set": {"status": "blocked"}})
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


@app.post("/dashboard/unblock")
async def unblock_device(request: Request, hwid: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.devices.update_one({"hwid": hwid}, {"$set": {"status": "approved"}})
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


@app.post("/dashboard/extend")
async def extend_device(request: Request, hwid: str = Form(...), days: int = Form(7)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    device = await db.devices.find_one({"hwid": hwid})
    if not device:
        raise HTTPException(404, "Device not found")
    base = datetime.utcnow()
    if device.get("expires_at") and device["expires_at"] > datetime.utcnow():
        base = device["expires_at"]
    await db.devices.update_one({"hwid": hwid}, {"$set": {"expires_at": base + timedelta(days=days), "status": "approved"}})
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


@app.post("/dashboard/delete")
async def delete_device(request: Request, hwid: str = Form(...)):
    if not _is_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")
    await db.devices.delete_one({"hwid": hwid})
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


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


@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
