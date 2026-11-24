"""Startpunkt: python -m spike_server"""
from __future__ import annotations

import asyncio
import sys

from aiohttp import web

from . import VERSION
from .api import build_app
from .config import RouterSettings, load
from .demo import Demo
from .discovery import Announcer
from .fritzbox import FritzBox
from .pairing import Pairing
from .snapshot import empty_snapshot, from_fritzbox
from .store import Store
from .tls import ensure_certificate, server_context


class State:
    def __init__(self):
        self.config = load()
        self.store = Store(self.config.data_dir / "state.json")
        self.pairing = Pairing()
        self.fritz = None
        self.demo = Demo(self.store) if self.config.demo else None
        self.cert_file, self.key_file, self.fingerprint = ensure_certificate(self.config.data_dir / "tls")

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
            raise PermissionError("Anmeldung fehlgeschlagen")
        self.fritz = fb
        print(f"[spike] Verbunden mit Router unter {router.host}", flush=True)
        return fb

    async def configure_router(self, host: str, user: str, password: str) -> None:
        settings = RouterSettings(host=host, user=user, password=password)
        await self._connect(settings)
        self.config.save_router(settings)
        self.demo = None

    async def snapshot(self) -> dict:
        if self.demo:
            return self.demo.snapshot()
        if self.fritz:
            return await from_fritzbox(self.fritz, self.store)
        return empty_snapshot(self.store)


async def main():
    state = State()
    await state.setup()
    if "--reset-pairing" in sys.argv:
        state.store.reset_pairing()
        print("Alle Kopplungen wurden zurückgesetzt. Starte Spike neu und verbinde die App erneut.")
        return
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
    try:
        await asyncio.Event().wait()
    finally:
        await announcer.stop()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
