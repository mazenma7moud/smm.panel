import os
import re
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

URL = os.environ["SUPABASE_URL"].rstrip("/")
ANON = os.environ["SUPABASE_ANON_KEY"]
SVC = os.environ["SUPABASE_SERVICE_KEY"]  # server only, never sent to the browser
ROOT = Path(__file__).resolve().parent.parent
H_SVC = {"apikey": SVC, "Authorization": f"Bearer {SVC}", "Content-Type": "application/json"}

app = FastAPI(docs_url=None, redoc_url=None)
# Auth uses Bearer tokens (no cookies), so open CORS is safe. Restrict with ALLOWED_ORIGINS="https://a.com,https://b.com" if you host the frontend elsewhere.
app.add_middleware(CORSMiddleware, allow_origins=os.environ.get("ALLOWED_ORIGINS", "*").split(","),
                   allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])


def rest(path: str) -> str:
    return f"{URL}/rest/v1/{path}"


async def user_id(auth: str | None) -> str:
    """Verify the Supabase JWT by asking Supabase itself."""
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "auth_required")
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(f"{URL}/auth/v1/user", headers={"apikey": ANON, "Authorization": auth})
    if r.status_code != 200:
        raise HTTPException(401, "auth_required")
    return r.json()["id"]


async def admin_id(auth: str | None) -> str:
    uid = await user_id(auth)
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(rest(f"profiles?id=eq.{uid}&select=role,banned"), headers=H_SVC)
    p = r.json()
    if not p or p[0]["role"] != "admin" or p[0]["banned"]:
        raise HTTPException(403, "forbidden")
    return uid


async def provider_creds(c: httpx.AsyncClient, pid: int):
    p = (await c.get(rest(f"providers?id=eq.{pid}&active=eq.true&select=api_url"), headers=H_SVC)).json()
    k = (await c.get(rest(f"provider_secrets?provider_id=eq.{pid}&select=api_key"), headers=H_SVC)).json()
    return (p[0]["api_url"], k[0]["api_key"]) if p and k else None


async def patch_order(c: httpx.AsyncClient, oid: int, data: dict):
    await c.patch(rest(f"orders?id=eq.{oid}"), headers=H_SVC, json=data)


async def forward(c: httpx.AsyncClient, oid: int):
    """Send a paid order to its provider once. Never retried automatically (avoids double orders)."""
    o = (await c.get(rest(f"orders?id=eq.{oid}&select=*,services(provider_id,provider_service_id)"), headers=H_SVC)).json()[0]
    s = o["services"]
    if o["provider_order_id"] or not s["provider_id"]:
        return  # manual order: admin handles it from the panel
    creds = await provider_creds(c, s["provider_id"])
    if not creds:
        return await patch_order(c, oid, {"error": "provider_unavailable"})
    url, key = creds
    try:
        d = (await c.post(url, data={"key": key, "action": "add", "service": s["provider_service_id"],
                                     "link": o["link"], "quantity": o["quantity"]})).json()
    except Exception:
        return await patch_order(c, oid, {"error": "provider_timeout_check_manually"})
    if "order" in d:
        await patch_order(c, oid, {"status": "Processing", "provider_order_id": str(d["order"]), "error": None})
    else:
        await patch_order(c, oid, {"error": str(d.get("error", "provider_error"))[:200]})


@app.get("/api/config")
async def config():
    return {"url": URL, "anon": ANON}


class LoginIn(BaseModel):
    identifier: str
    password: str


@app.post("/api/login")
async def login(b: LoginIn):
    """Username + password login. Resolves the username to its email on the server so emails are never exposed."""
    ident = b.identifier.strip()
    bad = HTTPException(400, "invalid_credentials")  # same answer for every failure
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", ident):
        raise bad
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(rest("profiles"), headers=H_SVC,
                        params={"select": "id", "username": "ilike." + ident.replace("_", "\\_")})
        rows = r.json() if r.status_code == 200 else []
        if len(rows) != 1:
            raise bad
        u = await c.get(f"{URL}/auth/v1/admin/users/{rows[0]['id']}", headers=H_SVC)
        email = u.json().get("email") if u.status_code == 200 else None
        if not email:
            raise bad
        t = await c.post(f"{URL}/auth/v1/token?grant_type=password",
                         headers={"apikey": ANON, "Content-Type": "application/json"},
                         json={"email": email, "password": b.password})
        if t.status_code != 200:
            raise bad
        d = t.json()
    return {"access_token": d["access_token"], "refresh_token": d["refresh_token"]}


class OrderIn(BaseModel):
    service_id: int
    link: str
    quantity: int
    key: str


@app.post("/api/orders")
async def new_order(o: OrderIn, authorization: str | None = Header(None)):
    await user_id(authorization)
    async with httpx.AsyncClient(timeout=30) as c:
        # runs as the user, so auth.uid() and RLS apply inside place_order
        r = await c.post(rest("rpc/place_order"),
                         headers={"apikey": ANON, "Authorization": authorization, "Content-Type": "application/json"},
                         json={"p_service": o.service_id, "p_link": o.link, "p_qty": o.quantity, "p_key": o.key})
        if r.status_code >= 400:
            raise HTTPException(400, r.json().get("message", "error"))
        oid = r.json()
        await forward(c, oid)
    return {"order_id": oid}


class ProviderIn(BaseModel):
    name: str
    api_url: str
    api_key: str


@app.post("/api/admin/provider")
async def add_provider(p: ProviderIn, authorization: str | None = Header(None)):
    uid = await admin_id(authorization)
    if not p.api_url.startswith("https://"):
        raise HTTPException(400, "api_url_must_be_https")
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(rest("providers"), headers={**H_SVC, "Prefer": "return=representation"},
                         json={"name": p.name, "api_url": p.api_url})
        pid = r.json()[0]["id"]
        await c.post(rest("provider_secrets"), headers=H_SVC, json={"provider_id": pid, "api_key": p.api_key})
        await c.post(rest("audit_logs"), headers=H_SVC,
                     json={"actor": uid, "action": "provider_added", "details": {"provider": pid}})
    return {"id": pid}


@app.post("/api/admin/sync")
async def sync(authorization: str | None = Header(None)):
    """Pull provider status for Processing orders; refund Canceled/Partial remains (idempotent)."""
    await admin_id(authorization)
    updated = 0
    async with httpx.AsyncClient(timeout=30) as c:
        rows = (await c.get(rest("orders?status=eq.Processing&select=id,user_id,unit_price,total,"
                                 "provider_order_id,services(provider_id)"), headers=H_SVC)).json()
        for o in rows:
            creds = await provider_creds(c, o["services"]["provider_id"])
            if not creds:
                continue
            try:
                d = (await c.post(creds[0], data={"key": creds[1], "action": "status",
                                                  "order": o["provider_order_id"]})).json()
            except Exception:
                continue
            st = d.get("status")
            if st not in ("Completed", "Partial", "Canceled"):
                continue
            refund = float(o["total"]) if st == "Canceled" else (
                round(float(d.get("remains", 0)) * float(o["unit_price"]) / 1000, 4) if st == "Partial" else 0)
            if refund > 0:  # refund first: if it fails the order stays Processing and is retried next sync
                r = await c.post(rest("rpc/wallet_apply"), headers=H_SVC, json={
                    "p_user": o["user_id"], "p_type": "refund", "p_amount": refund,
                    "p_ref": f"refund:{o['id']}", "p_reason": f"Provider {st} #{o['id']}", "p_order": o["id"]})
                if r.status_code >= 400:
                    continue
            await patch_order(c, o["id"], {"status": st})
            updated += 1
    return {"updated": updated}


for _name in ("style.css", "script.js", "config.js"):
    app.add_api_route(f"/{_name}", (lambda n=_name: FileResponse(ROOT / n)), methods=["GET"], include_in_schema=False)


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(ROOT / "index.html")
