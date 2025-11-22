# main.py
import os
import json
import hashlib
import hmac
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
import subprocess

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, status, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse, PlainTextResponse
import httpx
import atexit

# ---------- Config / paths (kept same as index.js) ----------
SECRET_FILE = Path("/home/iidk/site/secret.txt")
HASH_FILE = Path("/home/iidk/site/hashsecret.txt")
VOTES_FILE = Path("/home/iidk/site/votes.json")
SERVERDATA_FILE = Path("/home/iidk/site/serverdata.json")
PLAYERIDS_FILE = Path("/home/iidk/site/playerids.txt")
BANNEDIDS_FILE = Path("/home/iidk/site/bannedids.txt")

# external paths from your index.js
FRIENDDATA_DIR = Path("/mnt/external/site-data/Frienddata")
TELEM_DIR = Path("/mnt/external/site-data/Telemdata")
IPDATA_DIR = Path("/mnt/external/site-data/Ipdata")
TRANSLATED_DIR = Path("/mnt/external/site-data/Translatedata")
RECORDS_DB = Path("/mnt/external/site-data/records.db")  # used by sqlite in index.js

# load secrets (if present)
SECRET_KEY = SECRET_FILE.read_text().strip() if SECRET_FILE.exists() else ""
HASH_KEY = HASH_FILE.read_text().strip() if HASH_FILE.exists() else ""

# Default votes structure (same format used in index.js). See index.js votes handling. :contentReference[oaicite:3]{index=3}
if not VOTES_FILE.exists():
    VOTES_FILE.parent.mkdir(parents=True, exist_ok=True)
    VOTES_FILE.write_text(json.dumps({"a-votes": [], "b-votes": []}, indent=2))
_votes = json.loads(VOTES_FILE.read_text())

def save_votes():
    VOTES_FILE.write_text(json.dumps(_votes, indent=2))

def increment_vote(option: str, user_id: str) -> bool:
    if option not in ("a-votes", "b-votes"):
        raise ValueError('option must be "a-votes" or "b-votes"')
    if user_id in _votes["a-votes"] or user_id in _votes["b-votes"]:
        return False
    _votes[option].append(user_id)
    save_votes()
    return True

def reset_votes():
    _votes["a-votes"] = []
    _votes["b-votes"] = []
    save_votes()

def get_vote_counts():
    return {"a-votes": len(_votes["a-votes"]), "b-votes": len(_votes["b-votes"])}

# hash function (port of hashIpAddr using HMAC-SHA256). See index.js for exact behavior. :contentReference[oaicite:4]{index=4}
def hash_ip_addr(ip: str) -> str:
    key = HASH_KEY.encode("utf-8") if HASH_KEY else b""
    h = hmac.new(key, ip.encode("utf-8"), digestmod="sha256").digest()
    return h.hex()

# load serverdata if present (same as index.js) :contentReference[oaicite:5]{index=5}
serverdata = {"error": "No data"}
if SERVERDATA_FILE.exists():
    try:
        serverdata = json.loads(SERVERDATA_FILE.read_text())
    except Exception:
        serverdata = {"error": "No data"}

# load player id map (playerids.txt format: id;displayname), per index.js. :contentReference[oaicite:6]{index=6}
player_id_map: Dict[str, str] = {}
if PLAYERIDS_FILE.exists():
    for line in PLAYERIDS_FILE.read_text().splitlines():
        if ';' in line:
            uid, name = line.split(';', 1)
            player_id_map[uid.strip()] = name.strip()

# banned ids
banned_ids: List[str] = []
if BANNEDIDS_FILE.exists():
    banned_ids = [l for l in BANNEDIDS_FILE.read_text().splitlines() if l.strip()]

# in-memory caches & active structures (similar to index.js)
ip_request_timestamps: Dict[str, float] = {}
syncdata_timestamps: Dict[str, float] = {}
reportban_timestamps: Dict[str, float] = {}
getfriend_timestamps: Dict[str, float] = {}
friendmodify_timestamps: Dict[str, float] = {}
banned_ips: Dict[str, float] = {}
active_rooms: Dict[str, Dict[str, Any]] = {}
active_user_data: Dict[str, Dict[str, Any]] = {}

# Simple DB placeholder / record cache flush (index.js used sqlite; here we will stub flush logic
# so you can hook a real DB later)
record_cache: List[Dict[str, Any]] = []
MAX_CACHE_SIZE = 500

def write_record_cache(record: Dict[str, Any]):
    record_cache.append(record)
    if len(record_cache) >= MAX_CACHE_SIZE:
        flush_cache_to_db()

def flush_cache_to_db():
    # In index.js this flushed to sqlite3 at /mnt/external/site-data/records.db
    # Here we simply persist to a JSON file as a placeholder; replace with sqlite logic if desired.
    out = Path("/mnt/external/site-data/records_cache.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if out.exists():
        try:
            existing = json.loads(out.read_text())
        except Exception:
            existing = []
    existing.extend(record_cache.copy())
    out.write_text(json.dumps(existing, indent=2))
    record_cache.clear()

atexit.register(flush_cache_to_db)

# ---- WebSocket manager (raw WebSocket connections like the original) ----
class ConnectionManager:
    def __init__(self):
        # map iphash -> WebSocket
        self.active: Dict[str, WebSocket] = {}
        self.lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, client_ip: str):
        await ws.accept()
        ip_hash = hash_ip_addr(client_ip)
        async with self.lock:
            self.active[ip_hash] = ws
        print(f"Connected: {ip_hash} (# {len(self.active)})")
        return ip_hash

    async def disconnect(self, ip_hash: str):
        async with self.lock:
            self.active.pop(ip_hash, None)
        print(f"Disconnected: {ip_hash} (# {len(self.active)})")

    async def send_to(self, ip_hash: str, message: dict):
        ws = self.active.get(ip_hash)
        if ws:
            try:
                await ws.send_json(message)
            except Exception:
                pass

    async def broadcast(self, message: dict):
        async with self.lock:
            for ws in list(self.active.values()):
                try:
                    await ws.send_json(message)
                except Exception:
                    pass

    def is_online(self, ip_hash_or_ip: str) -> bool:
        # input may be ip or already hashed: try to detect
        # original code used ip -> hashed map; here we accept either one
        maybe_hash = ip_hash_or_ip
        if maybe_hash in self.active:
            ws = self.active[maybe_hash]
            # can't check state like ws.readyState, but presence is enough
            return True
        # if user passed raw ip, hash it
        candidate = hash_ip_addr(maybe_hash)
        return candidate in self.active

manager = ConnectionManager()

app = FastAPI(title="blankzz.online FastAPI port")

# -------------------- Helper utilities (mirrors JS helpers) --------------------
def clean_and_format_data(payload: dict) -> dict:
    # Port of cleanAndFormatData in index.js (truncated, similar behavior).
    d = {}
    d["directory"] = (payload.get("directory","") or "").upper()
    d["directory"] = "".join(ch for ch in d["directory"] if ch.isalnum())[:12]
    d["identity"] = "".join(ch for ch in (payload.get("identity","") or "").upper() if ch.isalnum())[:12]
    d["region"] = "".join(ch for ch in (payload.get("region","") or "").upper() if ch.isalnum())[:3]
    d["userid"] = "".join(ch for ch in (payload.get("userid","") or "").upper() if ch.isalnum())[:20]
    d["isPrivate"] = bool(payload.get("isPrivate", False))
    d["playerCount"] = max(-1, min(int(payload.get("playerCount", -1)), 10))
    d["gameMode"] = "".join(ch for ch in (payload.get("gameMode","") or "") if ch.isalnum())[:128].upper()
    d["consoleVersion"] = (payload.get("consoleVersion","") or "")[:8]
    d["menuName"] = "".join(ch for ch in (payload.get("menuName","") or "") if ch.isalnum())[:24]
    d["menuVersion"] = (payload.get("menuVersion","") or "")[:8]
    return d

def clean_and_format_syncdata(payload: dict) -> dict:
    # Simplified port of cleanAndFormatSyncData
    cleaned = {"directory": "", "region": "", "data": {}}
    cleaned["directory"] = "".join(ch for ch in (payload.get("directory","") or "").upper() if ch.isalnum())[:12]
    cleaned["region"] = "".join(ch for ch in (payload.get("region","") or "").upper() if ch.isalnum())[:3]
    rawdata = payload.get("data", {}) or {}
    count = 0
    for uid, user in rawdata.items():
        if count >= 10:
            break
        new_uid = "".join(ch for ch in uid if ch.isalnum()).upper()[:20]
        nickname = "".join(ch for ch in (user.get("nickname","") or "") if ch.isalnum())[:12].upper()
        cosmetics = (user.get("cosmetics","") or "")[:16384].upper()
        color = (user.get("color","") or "NULL")[:20]
        platform = (user.get("platform","") or "NULL")[:5]
        cleaned["data"][new_uid] = {
            "nickname": nickname,
            "cosmetics": cosmetics,
            "color": color,
            "platform": platform
        }
        count += 1
    return cleaned

# -------------------- HTTP Endpoints (port of many routes) --------------------
@app.get("/api/ping")
async def api_ping():
    return {"ok": True, "time": datetime.utcnow().isoformat() + "Z"}

@app.post("/telemetry")
async def telemetry(request: Request):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host
    # rate-limit per ip (like index.js)
    now = asyncio.get_event_loop().time()
    last = ip_request_timestamps.get(client_ip, 0)
    if now - last < 6:
        raise HTTPException(status_code=429, detail="rate limit")
    ip_request_timestamps[client_ip] = now

    # read body as json and validate with clean_and_format_data
    data = await request.json()
    try:
        cd = clean_and_format_data(data)
        active_rooms[cd["directory"]] = {
            "region": cd["region"],
            "gameMode": cd["gameMode"],
            "playerCount": cd["playerCount"],
            "isPrivate": cd["isPrivate"],
            "timestamp": int(datetime.utcnow().timestamp()*1000)
        }
        # write telem file like index.js
        TELEM_DIR.mkdir(parents=True, exist_ok=True)
        uid = cd.get("userid","NULL")
        (TELEM_DIR / f"{uid}.json").write_text(json.dumps({"ip": client_ip, "timestamp": int(datetime.utcnow().timestamp()*1000)}, indent=2))
        # optionally enqueue Discord webhook background task (not implemented here)
        return {"status": 200}
    except Exception:
        raise HTTPException(status_code=400, detail="bad request")

@app.post("/syncdata")
async def syncdata(request: Request):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host
    now = asyncio.get_event_loop().time()
    last = syncdata_timestamps.get(client_ip, 0)
    if now - last < 2.5:
        raise HTTPException(status_code=429, detail="rate limit")
    syncdata_timestamps[client_ip] = now

    data = await request.json()
    cd = clean_and_format_syncdata(data)
    active_user_data[cd["directory"]] = {"region": cd["region"], "roomdata": cd["data"], "timestamp": int(datetime.utcnow().timestamp()*1000)}
    # persist per original: write user records, send webhooks for special cosmetics (omitted)
    return {"status": 200}

@app.post("/reportban")
async def reportban(request: Request):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host
    now = asyncio.get_event_loop().time()
    last = reportban_timestamps.get(client_ip, 0)
    if now - last < 1800:
        raise HTTPException(status_code=429, detail="rate limit")
    reportban_timestamps[client_ip] = now
    payload = await request.json()
    # simplified: validate and call processBanData equivalent (omitted heavy logic)
    return {"status": 200}

@app.get("/votes")
async def get_votes():
    return get_vote_counts()

@app.post("/vote")
async def post_vote(request: Request):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host
    ip_hash = hash_ip_addr(client_ip)
    data = await request.json()
    opt = data.get("option")
    if increment_vote(opt, ip_hash):
        return get_vote_counts()
    raise HTTPException(status_code=400, detail="You have already voted")

# friend system: getfriends, frienduser, unfrienduser (simplified ports)
@app.post("/getfriends")
async def get_friends(request: Request):
    body = await request.json()
    key = body.get("key")
    if key == SECRET_KEY:
        uid = body.get("uid", "")
    else:
        client_ip = request.headers.get("x-forwarded-for") or request.client.host
        uid = hash_ip_addr(client_ip)
    friend_file = FRIENDDATA_DIR / f"{uid}.json"
    if not friend_file.exists():
        return {"friends": {}, "incoming": {}, "outgoing": {}}
    try:
        self_data = json.loads(friend_file.read_text())
    except Exception:
        return {"friends": {}, "incoming": {}, "outgoing": {}}
    # build return data using stored Telem/Ip data and cached records (this is heavy in original; simplified)
    return {"friends": {}, "incoming": {}, "outgoing": {}}

@app.post("/frienduser")
async def friend_user(request: Request):
    # full logic is long (reads telem files & frienddata and does many checks). We'll replicate core checks:
    client_ip = request.headers.get("x-forwarded-for") or request.client.host
    ip_hash = hash_ip_addr(client_ip)
    body = await request.json()
    target = body.get("uid","").strip()
    target = "".join(ch for ch in target if ch.isalnum())
    # TODO: replicate all checks from index.js: telem ip matching, friend limits, incoming/outgoing handling
    # For now, implement a simple append to friend files for demonstration
    FRIENDDATA_DIR.mkdir(parents=True, exist_ok=True)
    self_file = FRIENDDATA_DIR / f"{ip_hash}.json"
    if not self_file.exists():
        self_file.write_text(json.dumps({"private-ip": client_ip,"friends":[],"outgoing":[],"incoming":[]}, indent=2))
    tfile = FRIENDDATA_DIR / f"{target}.json"
    if not tfile.exists():
        tfile.write_text(json.dumps({"private-ip": "0.0.0.0","friends":[],"outgoing":[],"incoming":[]}, indent=2))
    sdata = json.loads(self_file.read_text())
    tdata = json.loads(tfile.read_text())
    # naive behavior: if incoming existed, accept; else push to outgoing/incoming
    if target in sdata.get("incoming", []):
        sdata["incoming"] = [x for x in sdata["incoming"] if x!=target]
        if ip_hash not in tdata["friends"]:
            tdata["friends"].append(ip_hash)
        if target not in sdata["friends"]:
            sdata["friends"].append(target)
    else:
        if target not in sdata["outgoing"]:
            sdata["outgoing"].append(target)
        if ip_hash not in tdata["incoming"]:
            tdata["incoming"].append(ip_hash)
    self_file.write_text(json.dumps(sdata, indent=2))
    tfile.write_text(json.dumps(tdata, indent=2))
    return {"status": 200}

@app.post("/unfrienduser")
async def unfriend_user(request: Request):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host
    ip_hash = hash_ip_addr(client_ip)
    body = await request.json()
    target = "".join(ch for ch in (body.get("uid","") or "") if ch.isalnum())
    sf = FRIENDDATA_DIR / f"{ip_hash}.json"
    tf = FRIENDDATA_DIR / f"{target}.json"
    if not sf.exists() or not tf.exists():
        raise HTTPException(status_code=400, detail="User files missing")
    sdata = json.loads(sf.read_text())
    tdata = json.loads(tf.read_text())
    # naive removal logic (mirrors index.js behavior)
    if target in sdata.get("friends", []):
        sdata["friends"] = [x for x in sdata["friends"] if x!=target]
        tdata["friends"] = [x for x in tdata["friends"] if x!=ip_hash]
    else:
        sdata["outgoing"] = [x for x in sdata.get("outgoing",[]) if x!=target]
        tdata["incoming"] = [x for x in tdata.get("incoming",[]) if x!=ip_hash]
    sf.write_text(json.dumps(sdata, indent=2))
    tf.write_text(json.dumps(tdata, indent=2))
    return {"status": 200}

# admin / server endpoints (inviteall, invite random, notify, blacklistid, addadmin, removeadmin, setpoll, etc.)
@app.post("/inviteall")
async def invite_all(request: Request):
    body = await request.json()
    if body.get("key") != SECRET_KEY:
        raise HTTPException(status_code=401)
    room = body.get("to","")
    # broadcast invite command (like index.js)
    await manager.broadcast({"command":"invite","from":"Server","to":room})
    return {"status":200}

@app.post("/notify")
async def notify_all(request: Request):
    body = await request.json()
    if body.get("key") != SECRET_KEY:
        raise HTTPException(status_code=401)
    await manager.broadcast({"command":"notification","from":"Server","message": body.get("message"), "time": body.get("time")})
    return {"status":200}

@app.post("/blacklistid")
async def blacklist_id(request: Request):
    body = await request.json()
    if body.get("key") != SECRET_KEY:
        raise HTTPException(status_code=401)
    idv = body.get("id")
    if idv:
        banned_ids.append(idv)
        BANNEDIDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        BANNEDIDS_FILE.write_text("\n".join(banned_ids))
    return {"status":200}

@app.post("/unblacklistid")
async def unblacklist_id(request: Request):
    body = await request.json()
    if body.get("key") != SECRET_KEY:
        raise HTTPException(status_code=401)
    idv = body.get("id")
    if idv and idv in banned_ids:
        banned_ids.remove(idv)
        BANNEDIDS_FILE.write_text("\n".join(banned_ids))
    return {"status":200}

# SQL endpoint (caution, dangerous — requires SECRET_KEY and runs arbitrary query)
@app.post("/sql")
async def run_sql(request: Request):
    body = await request.json()
    if body.get("key") != SECRET_KEY:
        raise HTTPException(status_code=401)
    query = body.get("query")
    # For safety we do not execute arbitrary SQL here. Return a placeholder.
    # Replace this with proper sqlite3 execution if you truly want that behavior.
    return {"status":200, "rows": [], "note": "SQL execution disabled in this port for safety. Re-enable carefully."}

# TTS endpoint (exec flite) - careful with shell escaping (index.js used exec)
@app.post("/tts")
async def tts(request: Request):
    body = await request.json()
    text = (body.get("text") or "")[:4096]
    if not text:
        raise HTTPException(status_code=400)
    # basic safe generation using flite if installed; else return 501
    output_path = Path("output.wav")
    try:
        # WARNING: this uses subprocess; ensure flite installed and sanitize input
        subprocess.run(["flite", "-t", text, "-o", str(output_path)], check=True, timeout=10)
        return FileResponse(path=str(output_path), media_type="audio/wav")
    except Exception as e:
        return JSONResponse({"status":500, "error": str(e)}, status_code=500)

# Translate endpoint uses Google translate API (as index.js did with translate.googleapis.com)
@app.post("/translate")
async def translate_text(request: Request):
    body = await request.json()
    text = (body.get("text") or "")[:4096]
    lang = (body.get("lang") or "es")[:6]
    if not text:
        raise HTTPException(status_code=400)
    # try cache
    h = hashlib.sha256(text.encode()).hexdigest()
    cache_dir = TRANSLATED_DIR / lang
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{h}.txt"
    if cache_file.exists():
        return {"translation": cache_file.read_text()}
    url = f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl={lang}&dt=t&q={httpx.utils.quote(text)}"
    async with httpx.AsyncClient() as client:
        r = await client.get(url, timeout=10.0)
        if r.status_code != 200:
            raise HTTPException(status_code=500, detail="translate failed")
        payload = r.json()
        translation = "".join([s[0] for s in payload[0]])
        cache_file.write_text(translation)
        return {"translation": translation}

# get userdata and gettelemdata endpoints (protected by SECRET_KEY like in index.js)
@app.post("/getuserdata")
async def get_userdata(request: Request):
    body = await request.json()
    if body.get("key") != SECRET_KEY:
        raise HTTPException(status_code=401)
    uid = "".join(ch for ch in (body.get("uid","") or "") if ch.isalnum())
    # Here we attempt to read cached records (the JSON file above)
    rec_file = Path("/mnt/external/site-data/records_cache.json")
    if not rec_file.exists():
        return {}
    try:
        recs = json.loads(rec_file.read_text())
        # find latest for uid
        latest = None
        for r in recs:
            if r.get("id") == uid:
                if not latest or r.get("timestamp",0) > latest.get("timestamp",0):
                    latest = r
        return latest or {}
    except Exception:
        return {}

@app.post("/gettelemdata")
async def get_telem_data(request: Request):
    body = await request.json()
    if body.get("key") != SECRET_KEY:
        raise HTTPException(status_code=401)
    uid = "".join(ch for ch in (body.get("uid","") or "") if ch.isalnum())
    f = TELEM_DIR / f"{uid}.json"
    if f.exists():
        return json.loads(f.read_text())
    return {}

# serverdata endpoint (public in index.js)
@app.get("/serverdata")
async def server_data():
    return json.loads(json.dumps(serverdata))

# simple rooms endpoint (requires SECRET_KEY)
@app.post("/rooms")
async def rooms(request: Request):
    body = await request.json()
    if body.get("key") != SECRET_KEY:
        raise HTTPException(status_code=401)
    # purge rooms older than 10 minutes like index.js
    now_ms = int(datetime.utcnow().timestamp() * 1000)
    to_del = [k for k,v in active_rooms.items() if now_ms - v.get("timestamp", now_ms) > 10*60*1000]
    for k in to_del: active_rooms.pop(k, None)
    return {"activeRooms": active_rooms}

# -------------------- WebSocket endpoint --------------------
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    # Accept connection and identify client IP (support Cloudflare header like index.js used 'cf-connecting-ip')
    client_ip = ws.headers.get("cf-connecting-ip") or ws.client.host
    ip_hash = await manager.connect(ws, client_ip)
    try:
        while True:
            data_text = await ws.receive_text()
            try:
                payload = json.loads(data_text)
            except Exception:
                continue
            cmd = payload.get("command")
            # Rate-limit socket messages (index.js had socketDelay; omitted here)
            if cmd == "invite":
                # send invite to a target if friends (original checks friend files)
                target = "".join(ch for ch in (payload.get("target","") or "") if ch.isalnum())
                room = "".join(ch for ch in (payload.get("room","") or "") if ch.isalnum()).upper()[:12]
                # naive: send invite to target if connected
                await manager.send_to(target, {"command":"invite","from": ip_hash, "to": room})
            elif cmd == "message":
                target = "".join(ch for ch in (payload.get("target","") or "") if ch.isalnum())
                message = payload.get("message")
                color = "".join(ch for ch in (payload.get("color","") or "") if ch.isalnum()).lower()[:12]
                await manager.send_to(target, {"command":"message","from": ip_hash, "message": message, "color": color})
            elif cmd == "reqinvite":
                target = "".join(ch for ch in (payload.get("target","") or "") if ch.isalnum())
                await manager.send_to(target, {"command":"reqinvite","from": ip_hash})
            elif cmd == "preferences":
                target = "".join(ch for ch in (payload.get("target","") or "") if ch.isalnum())
                prefs = payload.get("preferences")
                await manager.send_to(target, {"command":"preferences","from": ip_hash,"data": prefs})
            elif cmd == "theme":
                target = "".join(ch for ch in (payload.get("target","") or "") if ch.isalnum())
                theme = payload.get("theme")
                await manager.send_to(target, {"command":"theme","from": ip_hash,"data": theme})
            elif cmd == "macro":
                target = "".join(ch for ch in (payload.get("target","") or "") if ch.isalnum())
                macro = payload.get("macro")
                await manager.send_to(target, {"command":"macro","from": ip_hash,"data": macro})
            elif cmd == "close":
                break
            else:
                # unknown command - ignore
                pass

    except WebSocketDisconnect:
        await manager.disconnect(ip_hash)
    except Exception:
        await manager.disconnect(ip_hash)

# run instructions will be provided below
