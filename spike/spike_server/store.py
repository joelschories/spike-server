"""Dauerhafter Zustand: gekoppelte Geräte (nur Hashes der Schlüssel), vertraute Geräte, Ereignisse."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.data = {"server_id": str(uuid.uuid4()), "tokens": [], "devices": {}, "events": []}
        if path.exists():
            self.data.update(json.loads(path.read_text()))
        self.save()

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    @property
    def server_id(self) -> str:
        return self.data["server_id"]

    # --- Kopplung --------------------------------------------------------
    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def issue_token(self, device_name: str) -> str:
        token = secrets.token_urlsafe(32)
        self.data["tokens"].append({"hash": self._hash(token), "name": device_name[:60], "created": now_iso()})
        self.save()
        return token

    def token_valid(self, token: str) -> bool:
        h = self._hash(token)
        return any(secrets.compare_digest(t["hash"], h) for t in self.data["tokens"])

    def paired_count(self) -> int:
        return len(self.data["tokens"])

    # --- Geräte ------------------------------------------------------------
    def device(self, mac: str) -> dict:
        devices = self.data["devices"]
        if mac not in devices:
            devices[mac] = {"trusted": False, "name": None, "first_seen": now_iso()}
            self.save()
        return devices[mac]

    def update_device(self, mac: str, trusted: Optional[bool] = None, name: Optional[str] = None) -> None:
        d = self.device(mac)
        if trusted is not None:
            d["trusted"] = trusted
        if name:
            d["name"] = name[:60]
        self.save()

    def is_known(self, mac: str) -> bool:
        return mac in self.data["devices"]

    # --- Ereignisse -------------------------------------------------------
    def log(self, kind: str, title: str) -> None:
        self.data["events"].insert(0, {"id": str(uuid.uuid4()).upper(), "date": now_iso(), "kind": kind, "title": title})
        del self.data["events"][100:]
        self.save()

    def events(self, limit: int = 30) -> list:
        return self.data["events"][:limit]
