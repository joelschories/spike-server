"""Kopplung von iPhone/Mac mit dem Server.

- Solange noch kein Gerät gekoppelt ist, darf sich das erste Gerät ohne Code verbinden.
- Jedes weitere Gerät stellt eine Anfrage, die auf einem bereits gekoppelten Gerät
  erlaubt oder abgelehnt wird. Anfragen verfallen nach 10 Minuten.
- Höchstens 3 offene Anfragen gleichzeitig (gegen Fluten aus dem Heimnetz).
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

REQUEST_LIFETIME = 600
MAX_PENDING = 3


@dataclass
class PairRequest:
    id: str
    device_name: str
    created: float = field(default_factory=time.monotonic)
    status: str = "pending"          # pending | approved | denied
    token: Optional[str] = None      # wird genau einmal an das anfragende Gerät ausgeliefert

    @property
    def expired(self) -> bool:
        return time.monotonic() - self.created > REQUEST_LIFETIME


class Pairing:
    def __init__(self) -> None:
        self.requests: dict = {}

    def _cleanup(self) -> None:
        for rid in [r.id for r in self.requests.values() if r.expired]:
            del self.requests[rid]

    def pending(self) -> list:
        self._cleanup()
        return [r for r in self.requests.values() if r.status == "pending"]

    def create(self, device_name: str) -> Optional[PairRequest]:
        if len(self.pending()) >= MAX_PENDING:
            return None
        req = PairRequest(id=secrets.token_urlsafe(12), device_name=device_name[:60] or "Gerät")
        self.requests[req.id] = req
        return req

    def get(self, rid: str) -> Optional[PairRequest]:
        self._cleanup()
        return self.requests.get(rid)
