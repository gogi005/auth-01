import os
import json
import ssl
import time
import threading
import urllib.request
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from pydantic import BaseModel
from typing import Optional
import secrets

MONGO_URI = os.environ.get("MONGO_URI", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "zyper-admin-2026")
REAL_BASE = "https://license.zyper.app"
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", secrets.token_hex(32))

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


class DeviceRequest(BaseModel):
    hwid: str
    name: Optional[str] = ""
    days: Optional[int] = 7


class DeviceUpdate(BaseModel):
    hwid: str
    days: Optional[int] = None
    name: Optional[str] = None


def json_serial(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


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


async def get_db():
    return db


def require_auth(request: Request):
    token = request.cookies.get("auth_token")
    if token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True


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
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

DASHBOARD_SECRET = ADMIN_PASSWORD


def _check_admin(request: Request):
    auth = request.cookies.get("admin_token")
    if auth != ADMIN_PASSWORD:
        return False
    pw = request.query.get("pw")
    if pw == ADMIN_PASSWORD:
        return True
    return False


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
            "hwid": req_hwid,
            "name": "",
            "status": "pending",
            "created_at": datetime.utcnow(),
            "approved_at": None,
            "expires_at": None,
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
        "ok": True,
        "state": "valid",
        "hwid": req_hwid,
        "hasKey": True,
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
            "hwid": req_hwid,
            "name": "",
            "status": "pending",
            "created_at": datetime.utcnow(),
            "approved_at": None,
            "expires_at": None,
        })

    return JSONResponse({"ok": True, "state": "pending"})


@app.get("/v1/modules")
async def get_modules():
    cached = _get_cached("/v1/modules")
    if cached:
        status, headers, data = cached
        return JSONResponse(json.loads(data))
    return JSONResponse({"modules": []})


@app.get("/v1/social-modules")
async def get_social_modules():
    cached = _get_cached("/v1/social-modules")
    if cached:
        status, headers, data = cached
        return JSONResponse(json.loads(data))
    return JSONResponse({"modules": []})


@app.get("/v1/checker-modules")
async def get_checker_modules():
    cached = _get_cached("/v1/checker-modules")
    if cached:
        status, headers, data = cached
        return JSONResponse(json.loads(data))
    return JSONResponse({"modules": []})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not _check_admin(request):
        pw = request.query.get("pw", "")
        if pw == ADMIN_PASSWORD:
            resp = RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)
            resp.set_cookie("admin_token", ADMIN_PASSWORD, httponly=True, max_age=86400)
            return resp
        return HTMLResponse("""
        <html><head><title>Zyper Auth - Login</title>
        <style>
            body{background:#0a0a0a;color:#fff;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
            .login{background:#111;padding:40px;border:1px solid #333;border-radius:8px;text-align:center}
            input{background:#1a1a1a;color:#fff;border:1px solid #333;padding:12px;font-size:16px;border-radius:4px;width:250px}
            button{background:#00ff88;color:#000;border:none;padding:12px 30px;font-size:16px;border-radius:4px;cursor:pointer;margin-top:10px;font-weight:bold}
            button:hover{background:#00cc6a}
        </style></head>
        <body><div class="login">
            <h2>Zyper Auth Dashboard</h2>
            <form method="GET" action="/dashboard">
                <input type="password" name="pw" placeholder="Password" autofocus><br><br>
                <button type="submit">Login</button>
            </form>
        </div></body></html>
        """)

    if db is None:
        return HTMLResponse("<h1>Database not connected</h1>")

    devices = await db.devices.find().sort("created_at", -1).to_list(100)
    device_list = []
    for d in devices:
        remaining = None
        if d.get("expires_at"):
            rem = (d["expires_at"] - datetime.utcnow()).total_seconds()
            remaining = max(0, int(rem))
        device_list.append({
            "id": str(d["_id"]),
            "hwid": d["hwid"],
            "name": d.get("name", ""),
            "status": d["status"],
            "created_at": d["created_at"].isoformat() if d.get("created_at") else "",
            "approved_at": d["approved_at"].isoformat() if d.get("approved_at") else "",
            "expires_at": d["expires_at"].isoformat() if d.get("expires_at") else "N/A",
            "remaining_hours": round(remaining / 3600, 1) if remaining else None,
        })

    pending_count = sum(1 for d in device_list if d["status"] == "pending")
    active_count = sum(1 for d in device_list if d["status"] == "approved")

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "devices": device_list,
        "pending_count": pending_count,
        "active_count": active_count,
        "total_count": len(device_list),
        "admin_pw": ADMIN_PASSWORD,
    })


@app.post("/dashboard/approve")
async def approve_device(request: Request, hwid: str = Form(...), days: int = Form(7), name: str = Form("")):
    if not _check_admin(request):
        raise HTTPException(401, "Unauthorized")

    if db is None:
        raise HTTPException(500, "No database")

    expires = datetime.utcnow() + timedelta(days=days)
    await db.devices.update_one(
        {"hwid": hwid},
        {"$set": {
            "status": "approved",
            "name": name,
            "approved_at": datetime.utcnow(),
            "expires_at": expires,
        }}
    )
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


@app.post("/dashboard/block")
async def block_device(request: Request, hwid: str = Form(...)):
    if not _check_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")

    await db.devices.update_one(
        {"hwid": hwid},
        {"$set": {"status": "blocked"}}
    )
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


@app.post("/dashboard/unblock")
async def unblock_device(request: Request, hwid: str = Form(...)):
    if not _check_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")

    await db.devices.update_one(
        {"hwid": hwid},
        {"$set": {"status": "approved"}}
    )
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


@app.post("/dashboard/extend")
async def extend_device(request: Request, hwid: str = Form(...), days: int = Form(7)):
    if not _check_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")

    device = await db.devices.find_one({"hwid": hwid})
    if not device:
        raise HTTPException(404, "Device not found")

    base = datetime.utcnow()
    if device.get("expires_at") and device["expires_at"] > datetime.utcnow():
        base = device["expires_at"]

    new_expiry = base + timedelta(days=days)
    await db.devices.update_one(
        {"hwid": hwid},
        {"$set": {"expires_at": new_expiry, "status": "approved"}}
    )
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


@app.post("/dashboard/delete")
async def delete_device(request: Request, hwid: str = Form(...)):
    if not _check_admin(request):
        raise HTTPException(401, "Unauthorized")
    if db is None:
        raise HTTPException(500, "No database")

    await db.devices.delete_one({"hwid": hwid})
    return RedirectResponse(url=f"/dashboard?pw={ADMIN_PASSWORD}", status_code=302)


@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
