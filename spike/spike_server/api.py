"""HTTPS-API für die Spike-App."""
from __future__ import annotations

import traceback

from aiohttp import web

from . import VERSION
from .demo import _password
from .fritzbox import ConfirmationNeeded, RouterError


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
        if not public and request.remote:
            remote = request.remote[7:] if request.remote.startswith("::ffff:") else request.remote
            state.app_ips.add(remote)
        try:
            return await handler(request)
        except web.HTTPException:
            raise
        except ConfirmationNeeded as exc:
            # Die FRITZ!Box möchte die Änderung am Gerät bestätigt haben – die App zeigt die Anleitung
            return web.json_response({"confirm": exc.confirmation.public()}, status=428)
        except RouterError as exc:
            print(f"[spike] Router lehnt ab ({exc.code}): {exc.description}", flush=True)
            return web.json_response({"error": str(exc)}, status=400)
        except (ValueError, KeyError) as exc:
            return web.json_response({"error": str(exc) or "Ungültige Anfrage."}, status=400)
        except ConnectionError as exc:
            return web.json_response({"error": str(exc) or "Der Router ist gerade nicht erreichbar."}, status=503)
        except Exception as exc:
            traceback.print_exc()
            return web.json_response({"error": f"Im Spike-Server ist ein Fehler aufgetreten: {exc}"}, status=500)

    async def body(request) -> dict:
        try:
            data = await request.json()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    async def snapshot_response(fresh: bool = True):
        return web.json_response(await state.snapshot(fresh=fresh))

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

    @routes.get("/api/diagnostics")
    async def diagnostics(request):
        import platform
        fb = state.fritz
        return web.json_response({
            "version": VERSION, "mode": state.config.mode, "dataDir": str(state.config.data_dir),
            "python": platform.python_version(), "uptimeSeconds": int(__import__("time").time() - state.started),
            "router": state.config.router.host if state.router_ready else None,
            "routerServices": len(fb.control) if fb else 0,
            "dns": {"available": state.dns.available, "address": state.dns.bound, "port": state.dns.port,
                    "lists": state.dns.list_sizes, "problem": state.dns.problem},
            "log": list(state.log)[-120:],
        })

    # --- Kopplung -------------------------------------------------------------
    @routes.post("/api/pair")
    async def pair(request):
        name = str((await body(request)).get("deviceName", "Gerät"))[:60]
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
        if (await body(request)).get("approve"):
            req.status, req.token = "approved", store.issue_token(req.device_name)
            store.log("info", f"„{req.device_name}“ wurde verbunden")
        else:
            req.status = "denied"
            store.log("deviceBlocked", f"Verbindungsanfrage von „{req.device_name}“ abgelehnt")
        return web.json_response({"ok": True})

    # --- Router ----------------------------------------------------------------
    @routes.post("/api/router")
    async def router(request):
        data = await body(request)
        try:
            await state.configure_router(str(data.get("host", "")).strip() or "192.168.178.1",
                                         str(data.get("user", "")), str(data.get("password", "")))
        except (PermissionError, RouterError):
            return web.json_response({"error": "Benutzername oder Passwort stimmen nicht."}, status=400)
        except Exception:
            return web.json_response({"error": "Der Router ist unter dieser Adresse nicht erreichbar."}, status=400)
        store.log("info", "Router verbunden")
        return await snapshot_response()

    @routes.post("/api/router/settings")
    async def router_settings(request):
        await apply_settings(await body(request))
        return await snapshot_response()

    async def apply_settings(data: dict) -> None:
        fb = state.fritz
        if "wps" in data:
            on = bool(data["wps"])

            async def wps(token):
                if state.demo:
                    state.demo.set_check("wps", on)
                else:
                    await fb.set_wps(on, token)

            def done():
                state.overrides.set("wps", on)
                store.log("fixed" if not on else "info", "WPS deaktiviert" if not on else "WPS eingeschaltet")
            await state.router_action("WPS ausschalten" if not on else "WPS einschalten", wps, done)
        if "upnp" in data:
            on = bool(data["upnp"])

            async def upnp(token):
                if state.demo:
                    state.demo.set_check("upnp", on)
                else:
                    await fb.set_upnp(on, token)

            def done():
                state.overrides.set("upnp", on)
                store.log("fixed" if not on else "info", "UPnP deaktiviert" if not on else "UPnP eingeschaltet")
            await state.router_action("UPnP ausschalten" if not on else "UPnP einschalten", upnp, done)

    @routes.post("/api/router/reboot")
    async def reboot(request):
        async def go(token):
            if not state.demo:
                await state.fritz.reboot(token)
        await state.router_action("Router neu starten", go, lambda: store.log("info", "Router wird neu gestartet"))
        return web.json_response({"ok": True})

    @routes.get("/api/confirm/{cid}")
    async def confirmation(request):
        conf = state.confirmations.get(request.match_info["cid"])
        if conf is None:
            return web.json_response({"id": request.match_info["cid"], "title": "", "methods": [],
                                      "status": "expired", "message": "Diese Bestätigung ist abgelaufen."})
        return web.json_response(conf.public())

    @routes.delete("/api/confirm/{cid}")
    async def cancel_confirmation(request):
        await state.confirmations.cancel(state.fritz, request.match_info["cid"])
        return web.json_response({"ok": True})

    # --- Netzwerk ----------------------------------------------------------------
    @routes.get("/api/snapshot")
    async def snapshot(request):
        return await snapshot_response(fresh=False)

    @routes.post("/api/devices/trust")
    async def trust_many(request):
        data = await body(request)
        ids = [str(i) for i in data.get("ids", [])][:500]
        trusted = bool(data.get("trusted", True))
        for mac in ids:
            if state.demo:
                state.demo.set_device(mac, trusted, None, None)
            store.update_device(mac, trusted=trusted)
        if trusted:
            await release_auto_blocked(ids)
        if ids:
            store.log("deviceTrusted", f"{len(ids)} Geräte als vertraut markiert" if len(ids) > 1 else "Gerät als vertraut markiert")
        return await snapshot_response()

    async def release_auto_blocked(ids):
        """Vom strengen Modus gesperrte Geräte nach der Freigabe wieder ins Internet lassen."""
        held = [i for i in ids if store.meta(i).get("autoBlocked")]
        if not held:
            return
        snap = await state.snapshot()
        devs = [d for d in snap["devices"] if d["id"] in held]
        online = [d for d in devs if d.get("ip") or state.demo]

        async def unblock(token):
            for d in online:
                if state.demo:
                    state.demo.set_device(d["id"], None, False, None)
                else:
                    await state.fritz.set_blocked(d["ip"], False, token)

        def done():
            for d in online:
                state.overrides.set(f"block:{d['id']}", False)
            for i in held:
                offline = not any(d["id"] == i for d in online)
                store.update_device(i, autoBlocked=None, wantBlocked=False if offline else None)
        if online:
            await state.router_action("Gerät freigeben" if len(online) == 1 else f"{len(online)} Geräte freigeben",
                                      unblock, done)
        else:
            done()

    @routes.post("/api/security")
    async def security(request):
        """Strenger Modus: Neue Geräte kommen erst nach deiner Freigabe ins Internet."""
        data = await body(request)
        enabled = bool(data.get("strictMode"))
        if enabled and data.get("trustExisting"):
            snap = await state.snapshot()
            for d in snap["devices"]:
                if not d.get("isGuest") and not d.get("isBlocked"):
                    store.update_device(d["id"], trusted=True)
        if enabled:
            caller = request.remote[7:] if (request.remote or "").startswith("::ffff:") else request.remote
            snap = await state.snapshot()
            mine = next((d for d in snap["devices"] if d.get("ip") == caller), None)
            if mine:
                store.update_device(mine["id"], trusted=True)
        store.data["strictMode"] = enabled
        store.save()
        store.log("info", "Strenger Modus eingeschaltet: Neue Geräte brauchen deine Freigabe" if enabled
                  else "Strenger Modus ausgeschaltet")
        return await snapshot_response()

    @routes.post("/api/devices/block")
    async def block_many(request):
        """Mehrere Geräte auf einmal vom Internet trennen (eine Bestätigung an der FRITZ!Box für alle)."""
        data = await body(request)
        ids = {str(i) for i in data.get("ids", [])}
        snap = await state.snapshot()
        devs = [d for d in snap["devices"] if d["id"] in ids and (state.demo or (d.get("ip") and d.get("isOnline")))]
        later = [i for i in ids if not any(d["id"] == i for d in devs)]
        for mac in later:      # gerade offline: Spike sperrt beim nächsten Verbinden
            store.update_device(mac, wantBlocked=True, autoBlocked=None)
        if later:
            store.log("deviceBlocked", f"{len(later)} Geräte werden beim nächsten Verbinden gesperrt" if len(later) > 1
                      else "Gerät wird beim nächsten Verbinden gesperrt")
        if not devs:
            state.invalidate()
            return await snapshot_response()

        async def block(token):
            for d in devs:
                if state.demo:
                    state.demo.set_device(d["id"], None, True, None)
                else:
                    await state.fritz.set_blocked(d["ip"], True, token)

        def done():
            for d in devs:
                state.overrides.set(f"block:{d['id']}", True)
                store.update_device(d["id"], autoBlocked=None, wantBlocked=None)
            store.log("deviceBlocked", f"Internet für {len(devs)} Geräte gesperrt" if len(devs) > 1
                      else f"Internet für „{devs[0]['name']}“ gesperrt")
        await state.router_action(f"{len(devs)} Geräte sperren" if len(devs) > 1 else f"„{devs[0]['name']}“ sperren",
                                  block, done)
        return await snapshot_response()

    @routes.post("/api/devices/{id}")
    async def device(request):
        data = await body(request)
        mac = request.match_info["id"]
        trusted, blocked, name = data.get("trusted"), data.get("blocked"), data.get("name")
        if trusted is not None or name:
            if state.demo:
                state.demo.set_device(mac, trusted, None, name)
            store.update_device(mac, trusted=trusted, name=name)
            if trusted:
                store.log("deviceTrusted", "Gerät als vertraut markiert")
                if blocked is None:
                    await release_auto_blocked([mac])
        if blocked is not None:
            blocked = bool(blocked)
            snap = await state.snapshot()
            dev = next((d for d in snap["devices"] if d["id"] == mac), None)
            if dev is None:
                raise ValueError("Dieses Gerät kennt der Router nicht mehr.")
            if not state.demo and (not dev.get("ip") or not dev.get("isOnline")):
                # Offline: Die FRITZ!Box kann nur verbundene Geräte sperren. Spike erledigt das beim nächsten Verbinden.
                store.update_device(mac, wantBlocked=blocked, autoBlocked=None)
                store.log("deviceBlocked" if blocked else "deviceTrusted",
                          f"„{dev['name']}“ wird beim nächsten Verbinden gesperrt" if blocked
                          else f"„{dev['name']}“ wird beim nächsten Verbinden freigegeben")
                state.invalidate()
                return await snapshot_response()

            async def block(token):
                if state.demo:
                    state.demo.set_device(mac, None, blocked, None)
                else:
                    await state.fritz.set_blocked(dev["ip"], blocked, token)

            def done():
                state.overrides.set(f"block:{mac}", blocked)
                store.update_device(mac, wantBlocked=None, autoBlocked=None)
                store.log("deviceBlocked" if blocked else "deviceTrusted",
                          f"Internet für „{dev['name']}“ gesperrt" if blocked else f"„{dev['name']}“ wieder freigegeben")
            await state.router_action(f"„{dev['name']}“ sperren" if blocked else f"„{dev['name']}“ freigeben", block, done)
        return await snapshot_response()

    @routes.post("/api/devices/{id}/wake")
    async def wake(request):
        mac = request.match_info["id"]

        async def go(token):
            if not state.demo:
                await state.fritz.wake(mac, token)
        await state.router_action("Gerät aufwecken", go)
        return await snapshot_response()

    @routes.post("/api/guest")
    async def guest(request):
        enabled = bool((await body(request)).get("enabled"))

        async def go(token):
            if state.demo:
                state.demo.set_guest(enabled)
            else:
                await state.fritz.set_guest(enabled, token)

        def done():
            state.overrides.set("guest", enabled)
            store.log("guestOn" if enabled else "guestOff", "Gast-WLAN eingeschaltet" if enabled else "Gast-WLAN ausgeschaltet")
        await state.router_action("Gast-WLAN einschalten" if enabled else "Gast-WLAN ausschalten", go, done)
        return await snapshot_response()

    @routes.post("/api/guest/settings")
    async def guest_settings(request):
        """Gast-WLAN einrichten oder ändern: Name, Sichtbarkeit, einschalten. Fehlt ein Passwort, erzeugt Spike eines."""
        data = await body(request)
        ssid = str(data.get("ssid", "")).strip()[:32] or None
        hidden = data.get("hidden")
        if hidden:
            # Die FRITZ!Box kennt nur einen gemeinsamen Schalter für alle WLANs: „unsichtbar“ würde auch
            # das Heimnetz verstecken. Deshalb bietet Spike das nicht mehr an.
            raise ValueError("Die FRITZ!Box kann nur alle WLANs gemeinsam verstecken, nicht das Gast-WLAN allein. "
                             "Damit dein Heimnetz sichtbar bleibt, bleibt auch das Gast-WLAN sichtbar.")
        hidden = None if hidden is None else False
        enable = data.get("enable")
        snap = await state.snapshot()
        needs_password = not snap["guest"].get("password")
        password = _password() if needs_password else None
        if ssid is not None and len(ssid.encode()) > 32:
            raise ValueError("Der Name darf höchstens 32 Zeichen lang sein.")

        async def go(token):
            if state.demo:
                g = state.demo.guest
                if ssid: g["ssid"] = ssid
                if hidden is not None: g["hidden"] = bool(hidden)
                if password: g["password"] = password
                if enable is not None: g["enabled"] = bool(enable)
                g["configured"] = bool(g["ssid"] and g["password"])
                return
            fb = state.fritz
            if ssid:
                await fb.set_guest_ssid(ssid, token)
            if password:
                await fb.set_guest_password(password, token)
            if hidden is not None:
                await fb.set_all_visible(token)
            if enable is not None:
                await fb.set_guest(bool(enable), token)

        def done():
            if enable is not None:
                state.overrides.set("guest", bool(enable))
            if hidden is not None:
                state.overrides.set("guestHidden", bool(hidden))
            store.log("guestOn", "Gast-WLAN eingerichtet" if needs_password else "Gast-WLAN geändert")
        await state.router_action("Gast-WLAN einrichten" if needs_password else "Gast-WLAN ändern", go, done)
        return await snapshot_response()

    @routes.post("/api/guest/rotate")
    async def rotate(request):
        password = _password()

        async def go(token):
            if state.demo:
                state.demo.guest["password"] = password
            else:
                await state.fritz.set_guest_password(password, token)
        await state.router_action("Neues Gast-Passwort", go, lambda: store.log("guestPassword", "Gast-Passwort geändert"))
        return await snapshot_response()

    @routes.post("/api/checks/{id}/fix")
    async def fix(request):
        cid = request.match_info["id"]
        if cid not in ("wps", "upnp"):
            raise ValueError("Das kann Spike nicht automatisch beheben.")
        await apply_settings({cid: False})
        return await snapshot_response()

    @routes.post("/api/checks/{id}/dismiss")
    async def dismiss_check(request):
        """Empfehlung verwerfen: zählt nicht mehr in den Score, bis sich die Lage ändert (anderer Titel)."""
        cid = request.match_info["id"]
        data = await body(request)
        dismissed = store.data.setdefault("dismissed", {})
        if data.get("dismissed", True):
            snap = await state.snapshot()
            check = next((c for c in snap["checks"] if c["id"] == cid), None)
            if check is None:
                raise ValueError("Diese Empfehlung gibt es nicht mehr.")
            dismissed[cid] = check["title"]
            store.log("info", f"Empfehlung verworfen: {check['title']}")
        else:
            dismissed.pop(cid, None)
        store.save()
        return await snapshot_response()

    # --- Wächter -------------------------------------------------------------------
    @routes.post("/api/watch/settings")
    async def watch_settings(request):
        state.watcher.settings(await body(request))
        return await snapshot_response()

    @routes.post("/api/watch/alerts/{aid}")
    async def watch_alert(request):
        aid = request.match_info["aid"]
        action = (await body(request)).get("action")
        alert = state.watcher.find(aid)
        if alert is None:
            raise ValueError("Diesen Hinweis gibt es nicht mehr.")
        if action == "dismiss":
            state.watcher.resolve(aid, "dismissed")
        elif action == "trust":
            state.watcher.resolve(aid, "trusted")
            store.log("deviceTrusted", f"Wächter: „{alert['device']}“ ist in Ordnung")
        elif action == "block":
            snap = await state.snapshot()
            dev = next((d for d in snap["devices"] if d["id"] == alert["mac"]), None)
            if dev is None or not dev.get("ip"):
                raise ValueError("Das Gerät ist gerade nicht im Netz. Sperren geht, sobald es wieder verbunden ist.")

            async def block(token):
                if state.demo:
                    state.demo.set_device(dev["id"], None, True, None)
                else:
                    await state.fritz.set_blocked(dev["ip"], True, token)

            def done():
                state.overrides.set(f"block:{dev['id']}", True)
                state.watcher.resolve(aid, "blocked")
                store.log("deviceBlocked", f"Wächter: „{dev['name']}“ vom Internet getrennt")
            await state.router_action(f"„{dev['name']}“ sperren", block, done)
        else:
            raise ValueError("Unbekannte Aktion.")
        return await snapshot_response()

    # --- Schutzfilter ------------------------------------------------------------
    @routes.post("/api/filter")
    async def set_filter(request):
        data = await body(request)
        if not state.dns.available:
            raise ValueError(state.dns.problem or "Der Schutzfilter läuft auf diesem Gerät nicht.")
        before = state.dns.settings["enabled"]
        state.dns.update(data)
        if "enabled" in data and bool(data["enabled"]) != before:
            store.log("filter", "Schutzfilter eingeschaltet" if data["enabled"] else "Schutzfilter ausgeschaltet")
        if "pauseMinutes" in data:
            minutes = int(data["pauseMinutes"] or 0)
            store.log("filter", f"Schutzfilter für {minutes} Minuten pausiert" if minutes else "Schutzfilter läuft wieder")
        return await snapshot_response()

    @routes.post("/api/filter/domain")
    async def filter_domain(request):
        data = await body(request)
        list_name = data.get("list")
        if list_name not in ("allow", "block"):
            raise ValueError("Unbekannte Liste.")
        state.dns.set_domain(str(data.get("domain", "")), list_name, bool(data.get("add", True)))
        return await snapshot_response()

    app = web.Application(middlewares=[guard], client_max_size=64 * 1024)
    app.add_routes(routes)
    return app
