"""Einstellungen: aus den Home-Assistant-Add-on-Optionen (/data/options.json) oder aus Umgebungsvariablen."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    data_dir: Path
    port: int
    fritz_host: str
    fritz_user: str
    fritz_password: str
    server_name: str

    @property
    def router_configured(self) -> bool:
        return bool(self.fritz_user and self.fritz_password)


def load() -> Config:
    data_dir = Path(os.environ.get("SPIKE_DATA", "./data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    options: dict = {}
    options_file = data_dir / "options.json"
    if options_file.exists():
        options = json.loads(options_file.read_text())
    return Config(
        data_dir=data_dir,
        port=int(os.environ.get("SPIKE_PORT", "8765")),
        fritz_host=options.get("fritz_host") or os.environ.get("FRITZ_HOST", "192.168.178.1"),
        fritz_user=options.get("fritz_user") or os.environ.get("FRITZ_USER", ""),
        fritz_password=options.get("fritz_password") or os.environ.get("FRITZ_PASSWORD", ""),
        server_name=os.environ.get("SPIKE_NAME", "Spike-Server"),
    )
