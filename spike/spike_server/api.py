"""HTTP-API für die Spike-App."""
from __future__ import annotations

import ipaddress

from aiohttp import web

from . import VERSION, webui
from .demo import _password

# Home Assistant leitet die Seitenleiste (Ingress) von dieser Adresse aus weiter
INGRESS_SOURCES = {"172.30.32.2", "127.0.0.1", "::1"}


def _is_local_admin(request: web.Request) -> bool:
    return (request.remote or "") in INGRESS_SOURCES


def build_app(state) -> web.Application:
    routes = web.RouteTableDef()

    def authorized(request: web.Request) -> bool:
        header = request.headers.get("Authorization", "")
        return header.startswith("Bearer ") and state.store.token_valid(header[7:])

    @web.middleware
    async def guard(request, handler):
        public = request.path in ("/", "/api/info", "/api/pair")
        if not public and not authorized(request):
            return web.json_response({"error": "Nicht gekoppelt"}, status=401)
        return await handler(request)

    @routes.get("/")
    async def index(request):
        # Der Kopplungscode ist nur über Home Assistant (bzw. lokal) sichtbar, nicht im restlichen Netz.
        if not _is_local_admin(request):
            return web.Response(text="Spike läuft. Öffne Spike in der Home-Assistant-Seitenleiste.", content_type="text/plain")
        p = state.pairing
        return web.Response(text=webui.render(p.code, p.seconds_left, state.store.paired_count(),
                                              state.config.router_configured, p.locked()),
                            content_type="text/html")

    @routes.get("/api/info")
    async def info(request):
        return web.json_response({"name": state.config.server_name, "version": VERSION, "id": state.store.server_id,
                                  "routerConfigured": state.config.router_configured, "demo": state.demo is not None})

    @routes.post("/api/pair")
    async def pair(request):
        body = await request.json()
        if state.pairing.locked():
            return web.json_response({"error": "Zu viele Versuche. Bitte warte 5 Minuten."}, status=429)
        if not state.pairing.verify(str(body.get("code", ""))):
            return web.json_response({"error": "Der Code stimmt nicht."}, status=403)
        token = state.store.issue_token(str(body.get("deviceName", "Gerät")))
        state.store.log("info", f"„{body.get('deviceName', 'Gerät')}“ mit Spike gekoppelt")
        return web.json_response({"token": token, "id": state.store.server_id, "name": state.config.server_name})

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
        else:
            if blocked is not None:
                snap = await state.snapshot()
                ip = next((d["ip"] for d in snap["devices"] if d["id"] == mac), None)
                if ip:
                    await state.fritz.set_blocked(ip, bool(blocked))
        state.store.update_device(mac, trusted=trusted, name=name)
        if trusted:
            state.store.log("deviceTrusted", "Gerät als vertraut markiert")
        if blocked is not None:
            state.store.log("deviceBlocked" if blocked else "deviceTrusted",
                            "Internetzugang gesperrt" if blocked else "Gerät wieder freigegeben")
        return web.json_response(await state.snapshot())

    @routes.post("/api/guest")
    async def guest(request):
        enabled = bool((await request.json()).get("enabled"))
        if state.demo:
            state.demo.set_guest(enabled)
        else:
            await state.fritz.set_guest(enabled)
        state.store.log("guestOn" if enabled else "guestOff", "Gast-WLAN eingeschaltet" if enabled else "Gast-WLAN ausgeschaltet")
        return web.json_response(await state.snapshot())

    @routes.post("/api/guest/rotate")
    async def rotate(request):
        if state.demo:
            state.demo.rotate_guest()
        else:
            await state.fritz.set_guest_password(_password())
        state.store.log("guestPassword", "Gast-Passwort geändert")
        return web.json_response(await state.snapshot())

    @routes.post("/api/checks/{id}/fix")
    async def fix(request):
        cid = request.match_info["id"]
        if state.demo:
            state.demo.fix(cid)
        elif cid == "wps":
            await state.fritz.disable_wps()
        elif cid == "upnp":
            await state.fritz.disable_upnp()
        state.store.log("fixed", f"Behoben: {cid.upper()}")
        return web.json_response(await state.snapshot())

    @routes.post("/api/filter")
    async def set_filter(request):
        enabled = bool((await request.json()).get("enabled"))
        if state.demo:
            state.demo.set_filter(enabled)
        return web.json_response(await state.snapshot())

    app = web.Application(middlewares=[guard])
    app.add_routes(routes)
    return app
