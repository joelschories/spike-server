"""HTTPS-API für die Spike-App."""
from __future__ import annotations

from aiohttp import web

from . import VERSION
from .demo import _password


def build_app(state) -> web.Application:
    routes = web.RouteTableDef()
    store, pairing = state.store, state.pairing

    def authorized(request: web.Request) -> bool:
        header = request.headers.get("Authorization", "")
        return header.startswith("Bearer ") and store.token_valid(header[7:])

    @web.middleware
    async def guard(request, handler):
        public = request.path in ("/", "/api/info", "/api/pair") or request.path.startswith("/api/pair/")
        if not public and not authorized(request):
            return web.json_response({"error": "Dieses Gerät ist nicht mit Spike verbunden."}, status=401)
        return await handler(request)

    @routes.get("/")
    async def index(request):
        return web.Response(text="Spike läuft. Öffne die Spike-App, um dich zu verbinden.", content_type="text/plain")

    @routes.get("/api/info")
    async def info(request):
        return web.json_response({
            "name": state.config.server_name, "version": VERSION, "id": store.server_id,
            "mode": state.config.mode, "paired": store.paired_count() > 0,
            "routerConfigured": state.router_ready, "fingerprint": state.fingerprint,
        })

    # --- Kopplung -------------------------------------------------------------
    @routes.post("/api/pair")
    async def pair(request):
        body = await request.json()
        name = str(body.get("deviceName", "Gerät"))[:60]
        if store.paired_count() == 0:
            # Erstes Gerät: direkt verbinden
            token = store.issue_token(name)
            store.log("info", f"„{name}“ mit Spike verbunden")
            return web.json_response({"status": "approved", "token": token, "id": store.server_id,
                                      "name": state.config.server_name})
        req = pairing.create(name)
        if req is None:
            return web.json_response({"error": "Es warten schon zu viele Anfragen. Versuche es später erneut."}, status=429)
        store.log("info", f"„{name}“ möchte sich mit Spike verbinden")
        return web.json_response({"status": "pending", "requestId": req.id}, status=202)

    @routes.get("/api/pair/{rid}")
    async def pair_status(request):
        req = pairing.get(request.match_info["rid"])
        if req is None:
            return web.json_response({"status": "expired"})
        if req.status == "approved" and req.token:
            token, req.token = req.token, None   # nur einmal ausliefern
            return web.json_response({"status": "approved", "token": token, "id": store.server_id,
                                      "name": state.config.server_name})
        return web.json_response({"status": req.status})

    @routes.get("/api/pair-requests")
    async def pair_requests(request):
        return web.json_response([{"id": r.id, "deviceName": r.device_name} for r in pairing.pending()])

    @routes.post("/api/pair-requests/{rid}")
    async def decide(request):
        req = pairing.get(request.match_info["rid"])
        if req is None or req.status != "pending":
            return web.json_response({"error": "Diese Anfrage ist abgelaufen."}, status=404)
        if (await request.json()).get("approve"):
            req.status, req.token = "approved", store.issue_token(req.device_name)
            store.log("info", f"„{req.device_name}“ wurde verbunden")
        else:
            req.status = "denied"
            store.log("deviceBlocked", f"Verbindungsanfrage von „{req.device_name}“ abgelehnt")
        return web.json_response({"ok": True})

    # --- Router ----------------------------------------------------------------
    @routes.post("/api/router")
    async def router(request):
        body = await request.json()
        try:
            await state.configure_router(str(body.get("host", "")).strip() or "192.168.178.1",
                                         str(body.get("user", "")), str(body.get("password", "")))
        except PermissionError:
            return web.json_response({"error": "Benutzername oder Passwort stimmen nicht."}, status=400)
        except Exception:
            return web.json_response({"error": "Der Router ist unter dieser Adresse nicht erreichbar."}, status=400)
        store.log("info", "Router verbunden")
        return web.json_response(await state.snapshot())

    # --- Netzwerk ----------------------------------------------------------------
    @routes.get("/api/snapshot")
    async def snapshot(request):
        return web.json_response(await state.snapshot())

    @routes.post("/api/devices/{id}")
    async def device(request):
        body = await request.json()
        mac = request.match_info["id"]
        trusted, blocked, name = body.get("trusted"), body.get("blocked"), body.get("name")
        if state.demo:
            state.demo.set_device(mac, trusted, blocked, name)
        elif state.fritz and blocked is not None:
            snap = await state.snapshot()
            ip = next((d["ip"] for d in snap["devices"] if d["id"] == mac), None)
            if ip:
                await state.fritz.set_blocked(ip, bool(blocked))
        store.update_device(mac, trusted=trusted, name=name)
        if trusted:
            store.log("deviceTrusted", "Gerät als vertraut markiert")
        if blocked is not None:
            store.log("deviceBlocked" if blocked else "deviceTrusted",
                      "Internetzugang gesperrt" if blocked else "Gerät wieder freigegeben")
        return web.json_response(await state.snapshot())

    @routes.post("/api/guest")
    async def guest(request):
        enabled = bool((await request.json()).get("enabled"))
        if state.demo:
            state.demo.set_guest(enabled)
        elif state.fritz:
            await state.fritz.set_guest(enabled)
        store.log("guestOn" if enabled else "guestOff", "Gast-WLAN eingeschaltet" if enabled else "Gast-WLAN ausgeschaltet")
        return web.json_response(await state.snapshot())

    @routes.post("/api/guest/rotate")
    async def rotate(request):
        if state.demo:
            state.demo.rotate_guest()
        elif state.fritz:
            await state.fritz.set_guest_password(_password())
        store.log("guestPassword", "Gast-Passwort geändert")
        return web.json_response(await state.snapshot())

    @routes.post("/api/checks/{id}/fix")
    async def fix(request):
        cid = request.match_info["id"]
        if state.demo:
            state.demo.fix(cid)
        elif state.fritz and cid == "wps":
            await state.fritz.disable_wps()
        elif state.fritz and cid == "upnp":
            await state.fritz.disable_upnp()
        store.log("fixed", f"Behoben: {cid.upper()}")
        return web.json_response(await state.snapshot())

    @routes.post("/api/filter")
    async def set_filter(request):
        enabled = bool((await request.json()).get("enabled"))
        if state.demo:
            state.demo.set_filter(enabled)
        return web.json_response(await state.snapshot())

    app = web.Application(middlewares=[guard], client_max_size=64 * 1024)
    app.add_routes(routes)
    return app
