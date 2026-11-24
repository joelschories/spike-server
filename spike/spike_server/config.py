"""Einstellungen des Servers.

Die Router-Zugangsdaten kommen aus der App und liegen in <Datenordner>/router.json
(nur für den Spike-Dienst lesbar). Umgebungsvariablen dienen nur zum Testen.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RouterSettings:
    host: str = "192.168.178.1"
    user: str = ""
    password: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.user and self.password)


@dataclass
class Config:
    data_dir: Path
    port: int
    server_name: str
    mode: str            # "standalone" | "addon" | "docker"
    demo: bool           # nur zum Testen: Beispieldaten statt Router
    reset_pairing: bool
    router: RouterSettings

    @property
    def router_file(self) -> Path:
        return self.data_dir / "router.json"

    def save_router(self, router: RouterSettings) -> None:
        tmp = self.router_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(router.__dict__))
        os.chmod(tmp, 0o600)
        tmp.replace(self.router_file)
        self.router = router


def default_data_dir() -> str:
    """Home Assistant startet Add-ons über s6-overlay, dabei gehen Umgebungsvariablen aus dem
    Dockerfile verloren. Den Add-on-Speicher /data erkennt Spike deshalb selbst."""
    if os.environ.get("SPIKE_DATA"):
        return os.environ["SPIKE_DATA"]
    if os.path.isfile("/data/options.json") or (os.path.isdir("/data") and os.access("/data", os.W_OK)):
        return "/data"
    return "./data"


def load() -> Config:
    data_dir = Path(default_data_dir()).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(data_dir, 0o700)

    # Add-on-Optionen (Home Assistant legt sie hier ab); einzige Option: Kopplung zurücksetzen
    options = {}
    options_file = data_dir / "options.json"
    if options_file.exists():
        options = json.loads(options_file.read_text())

    router = RouterSettings(host=os.environ.get("FRITZ_HOST", "192.168.178.1"),
                            user=os.environ.get("FRITZ_USER", ""), password=os.environ.get("FRITZ_PASSWORD", ""))
    router_file = data_dir / "router.json"
    if router_file.exists():
        router = RouterSettings(**json.loads(router_file.read_text()))

    mode = "addon" if options_file.exists() else (os.environ.get("SPIKE_MODE") or "standalone")
    return Config(
        data_dir=data_dir,
        port=int(os.environ.get("SPIKE_PORT", "8765")),
        server_name=os.environ.get("SPIKE_NAME", "Spike"),
        mode=mode,
        demo=os.environ.get("SPIKE_DEMO") == "1",
        reset_pairing=bool(options.get("reset_pairing")) or os.environ.get("SPIKE_RESET_PAIRING") == "1",
        router=router,
    )
