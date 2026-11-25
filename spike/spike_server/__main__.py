"""Startpunkt: python -m spike_server"""
from __future__ import annotations

import asyncio
from datetime import datetime
import collections
import os
import signal
import sys
import time
import traceback
import uuid
from typing import Awaitable, Callable, Optional

from aiohttp import web

from . import VERSION
from .api import build_app
from .config import RouterSettings, load
from .demo import Demo
from .discovery import Announcer, lan_ip
from .dnsfilter import DnsFilter, dns_port, lan_ipv6
from .dhcpprobe import lan_dns_servers
from .fritzbox import Confirmation, ConfirmationNeeded, Confirmations, FritzBox
from .pairing import Pairing
from .snapshot import Overrides, empty_snapshot, from_fritzbox
from .store import Store
from .tls import ensure_certificate, server_context
from .snapshot import compute_score
from .watch import Watcher


class LogTail:
    """Schreibt die Ausgabe weiter und merkt sich die letzten Zeilen für die Diagnose in der App.
    Spike gibt nie Passwörter oder Schlüssel aus."""

    def __init__(self, stream, lines: collections.deque):
        self.stream, self.lines, self._part = stream, lines, ""

    def write(self, text: str) -> int:
        self.stream.write(text)
        self._part += text
        while "\n" in self._part:
            line, self._part = self._part.split("\n", 1)
            if line.strip():
                self.lines.append(f"{time.strftime('%H:%M:%S')} {line}")
        return len(text)

    def flush(self) -> None:
        self.stream.flush()


LOG = collections.deque(maxlen=200)
sys.stdout = LogTail(sys.stdout, LOG)
sys.stderr = LogTail(sys.stderr, LOG)


class State:
    def __init__(self):
        self.config = load()
        self.store = Store(self.config.data_dir / "state.json")
        self.pairing = Pairing()
        self.fritz: Optional[FritzBox] = None
        self.demo = Demo(self.store) if self.config.demo else None
        self.cert_file, self.key_file, self.fingerprint = ensure_certificate(self.config.data_dir / "tls")
        self.overrides = Overrides()
        self.confirmations = Confirmations()
        self.dns = DnsFilter(self.config.data_dir, dns_port(), lambda: self.config.router.host)
        self.ip = lan_ip()
        self.ipv6 = lan_ipv6()
        self.log = LOG
        self.started = time.time()
        self.watcher = Watcher(self.config.data_dir, self.store.log)
        self.dns.observer = self.watcher.observe
        self.watcher.quarantine = self._auto_quarantine
        self._snap = None
        self._snap_time = 0.0
        self._snap_lock = asyncio.Lock()

    @property
    def router_ready(self) -> bool:
        return self.demo is not None or self.fritz is not None

    async def setup(self):
        if self.config.reset_pairing:
            self.store.reset_pairing()
            print("[spike] Alle Kopplungen wurden zurückgesetzt.", flush=True)
        if self.config.router.configured and not self.demo:
            try:
                await self._connect(self.config.router)
            except Exception as exc:
                print(f"[spike] Router nicht erreichbar: {exc}", flush=True)

    async def _connect(self, router: RouterSettings) -> FritzBox:
        fb = FritzBox(router.host, router.user, router.password)
        await fb.connect()
        # Anmeldung prüfen: eine geschützte Abfrage muss klappen
        res = await fb.try_call("urn:dslforum-org:service:Hosts:1", "GetHostNumberOfEntries")
        if res is None:
            await fb.close()
            raise PermissionError("Anmeldung fehlgeschlagen")
        if self.fritz:
            await self.fritz.close()
        self.fritz = fb
        print(f"[spike] Verbunden mit Router unter {router.host}", flush=True)
        return fb

    async def configure_router(self, host: str, user: str, password: str) -> None:
        settings = RouterSettings(host=host, user=user, password=password)
        await self._connect(settings)
        self.config.save_router(settings)
        self.demo = None

    async def router_action(self, title: str, action: Callable[[Optional[str]], Awaitable[None]],
                            on_done: Optional[Callable[[], None]] = None) -> None:
        """Führt eine Änderung am Router aus. Verlangt die FRITZ!Box eine Bestätigung am Gerät,
        löst das `ConfirmationNeeded` aus; die App zeigt dann die Anleitung."""
        if self.demo:
            if os.environ.get("SPIKE_DEMO_CONFIRM") == "1":     # Bestätigung zum Testen nachstellen
                conf = Confirmation(id=uuid.uuid4().hex[:12], title=title, methods=["button", "dtmf;*11234"],
                                    token="demo", action=action, on_done=on_done)
                self.confirmations.items[conf.id] = conf

                async def finish():
                    await asyncio.sleep(6)
                    if conf.status == "waiting":
                        await action(None)
                        conf.status = "done"
                        if on_done:
                            on_done()
                conf.task = asyncio.ensure_future(finish())
                raise ConfirmationNeeded(conf)
            await action(None)
            if on_done:
                on_done()
            return
        if not self.fritz:
            raise ConnectionError("Spike ist noch mit keinem Router verbunden.")
        await self.confirmations.run(self.fritz, title, action, on_done)

    async def snapshot(self, fresh: bool = False) -> dict:
        """Gesamtbild, höchstens 4 Sekunden alt. Viele Apps können so alle paar Sekunden fragen,
        ohne dass die FRITZ!Box öfter als nötig abgefragt wird. Nach Änderungen: `fresh=True`."""
        now = time.time()
        if not fresh and self._snap is not None and now - self._snap_time < 4:
            return self._snap
        async with self._snap_lock:
            if not fresh and self._snap is not None and time.time() - self._snap_time < 4:
                return self._snap
            snap = await self._build_snapshot()
            self._snap, self._snap_time = snap, time.time()
            return snap

    def invalidate(self) -> None:
        self._snap = None

    async def watch(self) -> None:
        """Auch ohne geöffnete App regelmäßig nachsehen: neue Geräte, Gesundheit von Spike und Router."""
        tick = 0
        while True:
            await asyncio.sleep(30)
            tick += 1
            router_ok, router_detail = True, ""
            try:
                await self.snapshot()
            except Exception as exc:
                router_ok, router_detail = False, str(exc)
                print(f"[spike] Hintergrundprüfung fehlgeschlagen: {exc}", flush=True)
            if tick % 2 == 1:
                await self._check_health(router_ok, router_detail)
            if router_ok and (tick == 1 or tick % 120 == 0):
                await self._repair_visibility()
            self.watcher.save_if_needed()

    async def _repair_visibility(self) -> None:
        """Bis 0.5.0 konnte Spike das Gast-WLAN „unsichtbar“ schalten. Die FRITZ!Box versteckt dabei aber alle
        WLANs, auch das Heimnetz. Einmalig alle wieder sichtbar machen."""
        if not self.fritz or self.store.data.get("visibilityRepaired"):
            return
        try:
            hidden = await self.fritz.hidden_wlans()
            if hidden:
                await self.fritz.set_all_visible()
                self.store.log("info", "WLAN-Namen sind wieder sichtbar")
                print(f"[spike] WLAN-Namen wieder sichtbar gemacht ({hidden})", flush=True)
                self.invalidate()
            self.store.data["visibilityRepaired"] = True
            self.store.save()
        except Exception as exc:
            print(f"[spike] Konnte WLAN-Sichtbarkeit nicht prüfen: {exc}", flush=True)

    async def _check_health(self, router_ok: bool, router_detail: str) -> None:
        health = [await self.dns.health()]
        if self.fritz or self.demo:
            health.append({"id": "router", "title": "Verbindung zum Router", "ok": router_ok,
                           "detail": "Spike erreicht deine FRITZ!Box." if router_ok else router_detail})
        if self.dns.available:
            updated = self.dns.lists_updated
            fresh = False
            if updated:
                age = time.time() - datetime.fromisoformat(updated.replace("Z", "+00:00")).timestamp()
                fresh = age < 2 * 86400
            health.append({"id": "lists", "title": "Blocklisten", "ok": fresh,
                           "detail": "Aktuell, werden alle 6 Stunden erneuert." if fresh
                           else "Konnten länger nicht aktualisiert werden. Spike versucht es weiter."})
        self.watcher.health = health

    def _auto_quarantine(self, alert: dict) -> None:
        """Kritischer Fund und automatische Quarantäne eingeschaltet: Gerät sofort vom Internet trennen."""
        async def go():
            snap = self._snap or {}
            dev = next((d for d in snap.get("devices", []) if d["id"] == alert["mac"]), None)
            if not dev or not dev.get("ip"):
                return
            try:
                if self.demo:
                    self.demo.set_device(dev["id"], None, True, None)
                elif self.fritz:
                    await self.fritz.set_blocked(dev["ip"], True)
                self.overrides.set(f"block:{dev['id']}", True)
                alert["status"] = "blocked"
                self.store.log("deviceBlocked", f"Wächter hat „{dev['name']}“ vorsorglich vom Internet getrennt")
                self.invalidate()
            except Exception as exc:
                alert["detail"] += " Automatisches Sperren war nicht möglich: " + str(exc)
            self.watcher.save()
        asyncio.ensure_future(go())

    async def _build_snapshot(self) -> dict:
        snap = await self._router_snapshot()
        # Verworfene Empfehlungen zählen nicht mehr in den Score (gilt, bis sich die Lage ändert)
        dismissed = self.store.data.get("dismissed", {})
        for c in snap["checks"]:
            c["dismissed"] = dismissed.get(c["id"]) == c["title"] and c["status"] in ("warning", "critical", "info")
        # Wächter
        self.watcher.update_devices(snap["devices"], self.config.router.host, self.ip)
        names = {d["ip"]: d["name"] for d in snap["devices"] if d.get("ip")}
        lan_dns = await self._lan_dns()
        local_dns = None if lan_dns is None else self.ip in lan_dns
        snap["watch"] = self.watcher.snapshot(self.dns.clients_in_use(), dict(self.dns.client_queries), names,
                                              local_dns)
        if snap.get("routerConnected", True):
            snap["score"] = max(0, compute_score(snap["checks"], snap["devices"]) - self.watcher.penalty())
        return snap

    async def _lan_dns(self):
        """Welchen DNS-Server verteilt der Router per DHCP? Alle 5 Minuten neu gefragt."""
        if self.demo:
            return None
        now = time.time()
        cached = getattr(self, "_lan_dns_cache", None)
        if cached and now - cached[0] < 300:
            return cached[1]
        result = await lan_dns_servers(self.ip, self.config.router.host)
        if result is None and cached:
            result = cached[1]
        self._lan_dns_cache = (now, result)
        return result

    async def _router_snapshot(self) -> dict:
        if self.demo:
            snap = self.demo.snapshot()
            if self.dns.available:
                names = {d["ip"]: d["name"] for d in snap["devices"] if d.get("ip")}
                snap["filter"] = self.dns.snapshot(names, self.ip, self.ipv6, self.config.router.host)
            return snap
        if self.fritz:
            return await from_fritzbox(self.fritz, self.store, self.overrides, self.dns, self.ip, self.ipv6)
        return empty_snapshot(self.store, self.dns, self.ip, self.ipv6, self.config.router.host)


async def main():
    state = State()
    if "--reset-pairing" in sys.argv:
        state.store.reset_pairing()
        print("Alle Kopplungen wurden zurückgesetzt. Starte Spike neu und verbinde die App erneut.")
        return
    runner = announcer = None
    try:
        # Zuerst der DNS-Server: Das Heimnetz hängt an ihm, jede Sekunde ohne Antwort merkt man beim Surfen
        if os.environ.get("SPIKE_DNS", "1") != "0":
            await state.dns.start()
        await state.setup()
        runner = web.AppRunner(build_app(state), access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", state.config.port,
                          ssl_context=server_context(state.cert_file, state.key_file)).start()
        announcer = Announcer(state.config.server_name, state.config.port, state.store.server_id, VERSION,
                              state.fingerprint, state.config.mode)
        await announcer.start()
        watcher = asyncio.ensure_future(state.watch())
        print(f"[spike] Spike {VERSION} läuft verschlüsselt auf Port {state.config.port} ({state.config.mode}, "
              f"Daten in {state.config.data_dir})", flush=True)
        if state.store.paired_count() == 0:
            print("[spike] Noch kein Gerät verbunden – öffne die Spike-App, um dich zu verbinden.", flush=True)
        # Beim Beenden (systemd, Docker, Home Assistant senden SIGTERM) sauber aus dem Netz abmelden
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await stop.wait()
        watcher.cancel()
        print("[spike] Wird beendet, melde mich im Heimnetz ab …", flush=True)
    finally:
        # Auch nach einem Fehler alles freigeben, damit ein Neustart die Ports wieder bekommt
        for step in (announcer.stop() if announcer else None, state.dns.stop(),
                     runner.cleanup() if runner else None, state.fritz.close() if state.fritz else None):
            if step is not None:
                try:
                    await step
                except Exception:
                    pass


def run() -> None:
    """Startet Spike und fängt unerwartete Fehler ab: dann neu starten statt ganz auszufallen."""
    attempts = 0
    while True:
        try:
            asyncio.run(main())
            return                      # sauber beendet (SIGTERM)
        except KeyboardInterrupt:
            return
        except Exception:
            attempts += 1
            traceback.print_exc()
            wait = min(60, 5 * attempts)
            print(f"[spike] Unerwarteter Fehler, starte in {wait} Sekunden neu …", flush=True)
            time.sleep(wait)


if __name__ == "__main__":
    run()
