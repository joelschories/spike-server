"""Kopplung per 6-stelligem Code.

Sicherheit: Der Code gilt 10 Minuten und nur einmal. Nach 5 Fehlversuchen werden
weitere Versuche für 5 Minuten abgelehnt (gegen Durchprobieren im Heimnetz).
Der Code ist nur in Home Assistant (Ingress) bzw. im Server-Log sichtbar.
"""
from __future__ import annotations

import secrets
import time

CODE_LIFETIME = 600
MAX_FAILURES = 5
LOCKOUT = 300


class Pairing:
    def __init__(self) -> None:
        self._code = ""
        self._expires = 0.0
        self._failures: list = []
        self._locked_until = 0.0
        self.rotate()

    def rotate(self) -> None:
        self._code = f"{secrets.randbelow(1_000_000):06d}"
        self._expires = time.monotonic() + CODE_LIFETIME
        print(f"[spike] Kopplungscode: {self._code[:3]} {self._code[3:]} (gültig 10 Minuten)", flush=True)

    @property
    def code(self) -> str:
        if time.monotonic() > self._expires:
            self.rotate()
        return self._code

    @property
    def seconds_left(self) -> int:
        return max(0, int(self._expires - time.monotonic()))

    def locked(self) -> bool:
        return time.monotonic() < self._locked_until

    def verify(self, attempt: str) -> bool:
        if self.locked():
            return False
        attempt = "".join(ch for ch in attempt if ch.isdigit())
        if len(attempt) == 6 and secrets.compare_digest(attempt, self.code):
            self.rotate()  # nur einmal gültig
            return True
        now = time.monotonic()
        self._failures = [t for t in self._failures if now - t < LOCKOUT] + [now]
        if len(self._failures) >= MAX_FAILURES:
            self._locked_until = now + LOCKOUT
            self._failures.clear()
            print("[spike] Zu viele falsche Kopplungscodes – Kopplung 5 Minuten gesperrt.", flush=True)
        return False
