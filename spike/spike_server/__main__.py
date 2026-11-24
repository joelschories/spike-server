"""Startpunkt: python -m spike_server"""
from __future__ import annotations

import asyncio
import os
import signal
import sys
import uuid
from typing import Awaitable, Callable, Optional

from aiohttp import web

from . import VERSION
from .api import build_app
from .config import RouterSettings, load
from .demo import Demo
from .discovery import Announcer, lan_ip
from .dnsfilter import DnsFilter, dns_port, lan_ipv6
from .fritzbox import Confirmation, ConfirmationNeeded, Confirmations, FritzBox
from .pairing import Pairing
from .snapshot import Overrides, empty_snapshot, from_fritzbox
from .store import Store
from .tls import ensure_certificate, server_context


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

    async def snapshot(self) -> dict:
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
    await state.setup()
    if os.environ.get("SPIKE_DNS", "1") != "0":
        await state.dns.start()
    runner = web.AppRunner(build_app(state), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", state.config.port,
                      ssl_context=server_context(state.cert_file, state.key_file)).start()
    announcer = Announcer(state.config.server_name, state.config.port, state.store.server_id, VERSION,
                          state.fingerprint, state.config.mode)
    await announcer.start()
    print(f"[spike] Spike {VERSION} läuft verschlüsselt auf Port {state.config.port} ({state.config.mode})", flush=True)
    if state.store.paired_count() == 0:
        print("[spike] Noch kein Gerät verbunden – öffne die Spike-App, um dich zu verbinden.", flush=True)
    # Beim Beenden (systemd, Docker, Home Assistant senden SIGTERM) sauber aus dem Netz abmelden
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        print("[spike] Wird beendet, melde mich im Heimnetz ab …", flush=True)
        await announcer.stop()
        await state.dns.stop()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
