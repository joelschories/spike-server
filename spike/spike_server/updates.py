"""Prüft, ob es eine neuere Spike-Version gibt (öffentliche Versionsdatei im GitHub-Projekt).

Es wird nur diese eine Datei abgerufen, ohne Daten über das Heimnetz mitzuschicken.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

import httpx

VERSION_URL = "https://raw.githubusercontent.com/joelschories/spike-server/main/spike/config.yaml"


def parse(version: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version)[:3])


def newer(candidate: Optional[str], current: str) -> bool:
    return bool(candidate) and parse(candidate) > parse(current)


async def latest_version() -> Optional[str]:
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(VERSION_URL)
            r.raise_for_status()
        m = re.search(r'^version:\s*"?([0-9.]+)"?', r.text, re.MULTILINE)
        return m.group(1) if m else None
    except Exception as exc:
        print(f"[spike] Versionsprüfung nicht möglich: {exc}", flush=True)
        return None
