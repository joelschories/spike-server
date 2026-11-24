"""Spike-Wächter.

Lernt aus den DNS-Anfragen, wie sich jedes Gerät normalerweise verhält, und meldet Abweichungen:
- Hinweise auf Schadsoftware (zufällig aussehende Domains, wie sie Schadprogramme erzeugen),
- wiederholte Versuche, gefährliche Seiten zu erreichen,
- ungewöhnlich viele Anfragen im Vergleich zum gelernten Normalwert,
- neue Ziele bei Geräten, die sonst immer dieselben Server ansprechen (Kameras, Steckdosen, Lampen …).

Alles läuft lokal auf dem Spike-Server. Es verlassen keine Daten das Heimnetz.
"""
from __future__ import annotations

import json
import math
import os
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

LEARN_SECONDS = float(os.environ.get("SPIKE_WATCH_LEARN_HOURS", "72")) * 3600
# Geräte, die im Alltag immer dieselben wenigen Server ansprechen: hier sind neue Ziele auffällig
STEADY_KINDS = {"camera", "plug", "light", "vacuum"}
SEVERITY_PENALTY = {"critical": 20, "warning": 8, "info": 0}
VOWELS = set("aeiouy")


def now_iso(ts: Optional[float] = None) -> str:
    dt = datetime.fromtimestamp(ts or time.time(), timezone.utc)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def base_domain(name: str) -> str:
    parts = name.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "or", "ne"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def randomness(label: str) -> float:
    """0 … 1: Wie zufällig wirkt ein Domainname? Schadsoftware erzeugt oft Namen wie „xk2j9qpz7tm.com“."""
    label = label.lower()
    if len(label) < 10 or "-" in label:
        return 0.0
    counts = Counter(label)
    entropy = -sum(c / len(label) * math.log2(c / len(label)) for c in counts.values())
    letters = [ch for ch in label if ch.isalpha()]
    digits = sum(ch.isdigit() for ch in label)
    vowel_ratio = sum(ch in VOWELS for ch in letters) / max(1, len(letters))
    run = longest = 0
    for ch in label:
        run = run + 1 if ch.isalpha() and ch not in VOWELS else 0
        longest = max(longest, run)
    score = min(1.0, entropy / 4.0) * 0.45
    score += 0.2 if len(label) >= 14 else 0.1
    score += 0.2 if vowel_ratio < 0.25 else (0.1 if vowel_ratio < 0.32 else 0)
    score += 0.15 if digits >= 2 and len(letters) >= 4 else 0
    score += 0.15 if longest >= 5 else 0
    return min(1.0, score)


class Watcher:
    def __init__(self, data_dir: Path, log: Callable[[str, str], None]):
        self.file = data_dir / "watch.json"
        self.log = log
        self.devices: Dict[str, dict] = {}         # IP → {mac, name, kind}
        self.router_ip = ""
        self.self_ip = ""
        self.health: List[dict] = []
        self.quarantine: Optional[Callable[[dict], None]] = None
        self.data = {"enabled": True, "autoQuarantine": False, "profiles": {}, "alerts": [], "since": None}
        if self.file.exists():
            try:
                self.data.update(json.loads(self.file.read_text()))
            except Exception:
                pass
        self._dirty = False

    # --- Einstellungen ------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return bool(self.data["enabled"])

    def settings(self, body: dict) -> None:
        if "enabled" in body:
            self.data["enabled"] = bool(body["enabled"])
        if "autoQuarantine" in body:
            self.data["autoQuarantine"] = bool(body["autoQuarantine"])
        self.save()

    def save(self) -> None:
        tmp = self.file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data))
        tmp.replace(self.file)
        self._dirty = False

    def save_if_needed(self) -> None:
        if self._dirty:
            self.save()

    def update_devices(self, devices: List[dict], router_ip: str, self_ip: str) -> None:
        self.router_ip, self.self_ip = router_ip, self_ip
        self.devices = {d["ip"]: {"mac": d["id"], "name": d["name"], "kind": d["kind"]}
                        for d in devices if d.get("ip") and not d.get("isGuest")}

    # --- Beobachten ---------------------------------------------------------------
    def observe(self, ip: str, name: str, rcode: int, category: Optional[str]) -> None:
        if not self.enabled or ip.startswith("127.") or ip in (self.self_ip, self.router_ip, "::1"):
            return
        device = self.devices.get(ip)
        key = device["mac"] if device else ip
        now = time.time()
        if self.data["since"] is None:
            self.data["since"] = now
        p = self.data["profiles"].setdefault(key, {"first": now, "domains": {}, "mean": 0.0, "var": 0.0,
                                                   "hour": int(now // 3600), "count": 0, "hours": 0,
                                                   "threats": [], "random": [], "new": []})
        self._dirty = True
        learned = now - p["first"] > LEARN_SECONDS
        # Anfragen pro Stunde: gleitender Mittelwert und Streuung
        hour = int(now // 3600)
        if hour != p["hour"]:
            for _ in range(min(hour - p["hour"], 24)):
                x = p["count"]
                delta = x - p["mean"]
                p["mean"] += 0.08 * delta
                p["var"] = 0.92 * (p["var"] + 0.08 * delta * delta)
                p["count"] = 0
                p["hours"] += 1
            p["hour"], p["count"] = hour, 0
        p["count"] += 1

        base = base_domain(name)
        label = base.split(".")[0]
        known = base in p["domains"]
        if not known and len(p["domains"]) < 4000:
            p["domains"][base] = now

        # 1. Gefährliche Seite blockiert
        if category == "threats":
            p["threats"] = [t for t in p["threats"] if now - t[0] < 600] + [[now, name]]
            distinct = {t[1] for t in p["threats"]}
            if len(distinct) >= 3:
                self._alert(key, device, ip, "threats", "critical", "Mehrere gefährliche Seiten in kurzer Zeit",
                            "Das Gerät hat in den letzten Minuten mehrfach versucht, bekannte Betrugs- oder "
                            "Schadsoftware-Seiten zu erreichen. Das kann auf Schadsoftware hindeuten.", sorted(distinct))
            else:
                self._alert(key, device, ip, "threat", "warning", "Gefährliche Seite blockiert",
                            "Spike hat den Aufruf einer bekannten Betrugs- oder Schadsoftware-Seite verhindert. "
                            "Oft steckt ein Klick auf einen Link dahinter.", [name])

        # 2. Zufällig wirkende Domains (typisch für Schadsoftware, die ihre Server sucht)
        if not known and randomness(label) >= 0.75:
            p["random"] = [r for r in p["random"] if now - r[0] < 900] + [[now, base, rcode]]
            distinct = {r[1] for r in p["random"]}
            failed = sum(1 for r in p["random"] if r[2] == 3)
            if len(distinct) >= 4 and failed >= 2:
                self._alert(key, device, ip, "random", "critical", "Hinweise auf Schadsoftware",
                            "Das Gerät fragt viele zufällig aussehende Adressen ab, von denen die meisten nicht "
                            "existieren. Genau so suchen Schadprogramme ihre Steuerserver.", sorted(distinct)[:8])

        # 3. Ungewöhnlich viele Anfragen
        if learned and p["hours"] >= 24:
            std = math.sqrt(max(p["var"], 1.0))
            limit = max(200, p["mean"] * 4, p["mean"] + 6 * std)
            if p["count"] > limit:
                self._alert(key, device, ip, "volume", "warning", "Ungewöhnlich viele Anfragen",
                            f"In dieser Stunde schon {p['count']} Anfragen, normal sind etwa {int(p['mean'])}. "
                            "Das kann ein Update sein, aber auch ein Gerät, das sich verdächtig verhält.", [])

        # 4. Neue Ziele bei Geräten mit festem Verhalten
        if learned and not known and category is None and device and device["kind"] in STEADY_KINDS:
            p["new"] = [n for n in p["new"] if now - n[0] < 3600] + [[now, base]]
            distinct = sorted({n[1] for n in p["new"]})
            if len(distinct) >= 3:
                self._alert(key, device, ip, "new", "warning", "Spricht plötzlich mit neuen Servern",
                            "Dieses Gerät verbindet sich normalerweise immer mit denselben Servern. Jetzt kamen "
                            "mehrere neue dazu. Nach einem Firmware-Update ist das normal, sonst lohnt ein Blick.",
                            distinct[:8])

    def _alert(self, key: str, device: Optional[dict], ip: str, kind: str, severity: str, title: str,
               detail: str, evidence: List[str]) -> None:
        now = time.time()
        for a in self.data["alerts"]:
            if a["key"] == key and a["kind"] == kind and now - a["updated"] < 6 * 3600:
                if a["status"] == "open":
                    a["count"] += 1
                    a["updated"] = now
                    a["evidence"] = sorted(set(a["evidence"]) | set(evidence))[:12]
                return
        alert = {"id": uuid.uuid4().hex[:12], "key": key, "ip": ip, "mac": device["mac"] if device else None,
                 "device": device["name"] if device else ip, "kind": kind, "severity": severity, "title": title,
                 "detail": detail, "evidence": evidence[:12], "count": 1, "created": now, "updated": now,
                 "status": "open"}
        self.data["alerts"].insert(0, alert)
        del self.data["alerts"][200:]
        self.log("newDevice" if severity == "critical" else "filter", f"Wächter: {title} ({alert['device']})")
        if severity == "critical" and self.data["autoQuarantine"] and alert["mac"] and self.quarantine:
            self.quarantine(alert)

    # --- Aktionen aus der App -----------------------------------------------------
    def find(self, aid: str) -> Optional[dict]:
        return next((a for a in self.data["alerts"] if a["id"] == aid), None)

    def resolve(self, aid: str, status: str) -> Optional[dict]:
        a = self.find(aid)
        if a:
            a["status"] = status
            if status == "trusted":
                # „Ist in Ordnung“: die Ziele gehören ab jetzt zum normalen Verhalten
                p = self.data["profiles"].get(a["key"])
                if p:
                    for d in a["evidence"]:
                        p["domains"][base_domain(d)] = time.time()
                    p["random"], p["new"], p["threats"] = [], [], []
            self.save()
        return a

    # --- Für die App ---------------------------------------------------------------
    def snapshot(self, dns_clients: List[str], client_queries: Dict[str, int], names: Dict[str, str]) -> dict:
        now = time.time()
        per_device = [c for c in dns_clients if c not in (self.router_ip, self.self_ip) and not c.startswith("127.")]
        if not self.enabled:
            status = "off"
        elif not per_device:
            status = "routerOnly"
        elif self.data["since"] and now - self.data["since"] < LEARN_SECONDS:
            status = "learning"
        else:
            status = "active"
        open_alerts = [a for a in self.data["alerts"] if a["status"] == "open"]
        learned = sum(1 for p in self.data["profiles"].values() if now - p["first"] > LEARN_SECONDS)
        top = sorted(((names.get(ip, ip), n) for ip, n in client_queries.items()
                      if ip not in (self.router_ip, self.self_ip) and not ip.startswith("127.")),
                     key=lambda x: -x[1])[:5]
        return {
            "enabled": self.enabled,
            "status": status,
            "autoQuarantine": bool(self.data["autoQuarantine"]),
            "learningUntil": now_iso(self.data["since"] + LEARN_SECONDS) if self.data["since"] else None,
            "devicesWatched": len(self.data["profiles"]),
            "devicesLearned": learned,
            "alerts": [{"id": a["id"], "device": a["device"], "deviceId": a["mac"], "kind": a["kind"],
                        "severity": a["severity"], "title": a["title"], "detail": a["detail"],
                        "evidence": a["evidence"], "count": a["count"], "date": now_iso(a["updated"]),
                        "status": a["status"]} for a in self.data["alerts"][:30]],
            "openAlerts": len(open_alerts),
            "health": self.health,
            "topDevices": [{"name": n, "queries": q} for n, q in top],
        }

    def penalty(self) -> int:
        return sum(SEVERITY_PENALTY.get(a["severity"], 0) for a in self.data["alerts"] if a["status"] == "open")
