"""Startpunkt: python -m spike_server"""
from __future__ import annotations

import asyncio

from aiohttp import web

from . import VERSION
from .api import build_app
from .config import load
from .demo import Demo
from .discovery import Announcer
from .fritzbox import FritzBox
from .pairing import Pairing
from .snapshot import from_fritzbox
from .store import Store


class State:
    def __init__(self):
        self.config = load()
        self.store = Store(self.config.data_dir / "state.json")
        self.pairing = Pairing()
        self.fritz = None
        self.demo = None

    async def setup(self):
        if self.config.router_configured:
            self.fritz = FritzBox(self.config.fritz_host, self.config.fritz_user, self.config.fritz_password)
            await self.fritz.connect()
            print(f"[spike] Verbunden mit Router unter {self.config.fritz_host}", flush=True)
        else:
            self.demo = Demo(self.store)
            print("[spike] Keine Router-Zugangsdaten – Demo-Modus mit Beispieldaten.", flush=True)

    async def snapshot(self) -> dict:
        if self.demo:
            return self.demo.snapshot()
        return await from_fritzbox(self.fritz, self.store)


async def main():
    state = State()
    await state.setup()
    app = build_app(state)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", state.config.port).start()
    announcer = Announcer(state.config.server_name, state.config.port, state.store.server_id, VERSION)
    await announcer.start()
    print(f"[spike] Spike {VERSION} läuft auf Port {state.config.port}", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await announcer.stop()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
