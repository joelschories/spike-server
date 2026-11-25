"""Eingebauter Schutzfilter.

Ein kleiner DNS-Server für das ganze Heimnetz:
- blockiert Werbung, Tracker, Betrug und Schadsoftware (Blocklisten von HaGeZi, täglich aktualisiert),
- leitet alle übrigen Anfragen verschlüsselt weiter (DNS over HTTPS, Quad9/Cloudflare/Google),
- fragt für Namen aus dem Heimnetz (fritz.box, Rückwärtsauflösung) direkt den Router,
- kann SafeSearch bei Suchmaschinen und YouTube erzwingen.

Auch wenn der Filter ausgeschaltet oder pausiert ist, beantwortet Spike weiter alle Anfragen.
So bleibt das Internet erreichbar, solange der Router Spike als DNS-Server nutzt.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import random
import re
import socket
import struct
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import httpx

LIST_BASE = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/"

# Kategorien. Reihenfolge = Anzeige in der App.
# "lists": HaGeZi-Listen (normal), "strict": Listen im strengen Modus, "builtin": fest eingebaute Adressen.
CATEGORIES = {
    "ads": {"title": "Werbung & Tracker", "lists": ["pro"], "strict": ["pro.plus"], "default": True,
            "builtin": ["adservice.google.com", "adservice.google.de", "googletagservices.com",
                        # Werbung und Werbeblocker-Umgehung großer deutscher Nachrichtenseiten
                        "asadcdn.com", "html-load.com", "tisoomi.com", "s.tstat.net"],
            "detail": "Werbebanner, Pop-ups, Tracker, Telemetrie und Datensammler."},
    "threats": {"title": "Betrug & Schadsoftware", "lists": ["tif.medium"], "default": True,
                "detail": "Phishing, Fake-Shops, Abzocke, Schadsoftware und Krypto-Miner."},
    "bypass": {"title": "Umgehung verhindern", "lists": ["doh-vpn-proxy-bypass"], "default": True, "nxdomain": True,
               "builtin": ["use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com",
                           "mask-api.icloud.com", "mask-t.apple-dns.net"],
               # Fernzugänge fürs eigene Heimnetz nicht kaputt machen
               "except": ["tailscale.com", "tailscale.io", "ts.net", "zerotier.com", "nabu.casa", "wireguard.com",
                          "myfritz.net", "fritz.box", "plex.tv", "remote.it"],
               "detail": "Sperrt fremde DNS-Dienste, Proxys und iCloud Privat-Relay im Heimnetz, damit Browser und "
                         "Apps nicht am Filter vorbei surfen. Unterwegs bleibt Privat-Relay aktiv."},
    "native": {"title": "Hersteller-Tracking", "default": False,
               "lists": ["native.samsung", "native.lgwebos", "native.amazon", "native.tiktok", "native.winoffice",
                         "native.xiaomi", "native.huawei", "native.roku", "native.vivo", "native.oppo-realme"],
               "detail": "Nutzungsdaten, die Fernseher, Handys, Windows und smarte Lautsprecher an ihre Hersteller senden."},
    "social": {"title": "Soziale Netzwerke", "default": False,
               "builtin": ["facebook.com", "facebook.net", "fbcdn.net", "fb.com", "fb.me", "messenger.com",
                           "instagram.com", "cdninstagram.com", "ig.me", "threads.net", "threads.com",
                           "tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-eu.com", "tiktokv.eu",
                           "byteoversea.com", "ibytedtos.com", "musical.ly", "snapchat.com", "snap.com",
                           "sc-cdn.net", "snapkit.com", "x.com", "twitter.com", "twimg.com", "t.co",
                           "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "pinterest.com",
                           "pinterest.de", "pinimg.com", "tumblr.com", "bsky.app", "bsky.social", "vk.com",
                           "likee.video", "lemon8-app.com", "bereal.com", "triller.co"],
               "detail": "Instagram, TikTok, Facebook, Snapchat, X, Reddit, Pinterest und weitere."},
    "gambling": {"title": "Glücksspiel", "lists": ["gambling.medium"], "default": False,
                 "detail": "Online-Casinos, Sportwetten und Lotterien."},
    "adult": {"title": "Erwachseneninhalte", "lists": ["nsfw"], "default": False,
              "detail": "Pornografische und andere nicht jugendfreie Seiten."},
}
CATEGORY_LABEL = {"ads": "Werbung", "threats": "Gefahr", "gambling": "Glücksspiel", "adult": "Jugendschutz",
                  "bypass": "Umgehung", "native": "Hersteller", "social": "Soziale Netzwerke", "custom": "Eigene Liste"}

UPSTREAMS = {
    "quad9": ["https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"],
    "cloudflare": ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"],
    "google": ["https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"],
}
PLAIN_FALLBACK = ["9.9.9.9", "1.1.1.1"]

# SafeSearch: Suchmaschinen liefern unter diesen Namen nur gefilterte Ergebnisse.
SAFESEARCH = [
    (re.compile(r"^(www\.)?google\.[a-z]{2,3}(\.[a-z]{2})?$"), "forcesafesearch.google.com"),
    (re.compile(r"^(www\.|m\.)?youtube\.com$|^youtubei\.googleapis\.com$|^youtube\.googleapis\.com$"
                r"|^www\.youtube-nocookie\.com$"), "restrictmoderate.youtube.com"),
    (re.compile(r"^(www\.)?bing\.com$"), "strict.bing.com"),
    (re.compile(r"^(www\.)?duckduckgo\.com$"), "safe.duckduckgo.com"),
]

LOCAL_SUFFIXES = (".fritz.box", ".box", ".lan", ".local", ".home.arpa", ".internal")
T_A, T_AAAA, T_CNAME, T_HTTPS = 1, 28, 5, 65


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --- DNS-Pakete ------------------------------------------------------------------

def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Liest einen (ggf. komprimierten) Namen. Gibt Name und Ende im Originalpaket zurück."""
    labels: List[str] = []
    end = None
    jumps = 0
    while True:
        if offset >= len(data):
            raise ValueError("Name zu kurz")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            if jumps > 20:
                raise ValueError("Schleife")
            continue
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), (end if end is not None else offset)


def parse_query(data: bytes) -> Optional[Tuple[str, int, int]]:
    """(Name in Kleinbuchstaben, Typ, Ende der Frage) oder None bei kaputten Paketen."""
    if len(data) < 17:
        return None
    qd = struct.unpack(">H", data[4:6])[0]
    if qd != 1:
        return None
    try:
        name, off = _read_name(data, 12)
        qtype = struct.unpack(">H", data[off:off + 2])[0]
    except (ValueError, struct.error):
        return None
    return name.lower().rstrip("."), qtype, off + 4


def _response(query: bytes, qend: int, rcode: int, answers: bytes = b"", ancount: int = 0) -> bytes:
    rd = query[2] & 0x01
    flags = 0x8000 | (rd << 8) | 0x0080 | rcode       # QR, RD übernommen, RA
    header = query[:2] + struct.pack(">HHHHH", flags, 1, ancount, 0, 0)
    return header + query[12:qend] + answers


def blocked_response(query: bytes, qtype: int, qend: int) -> bytes:
    """Gesperrt: 0.0.0.0 bzw. :: – Apps scheitern sofort statt zu warten."""
    if qtype == T_A:
        return _response(query, qend, 0, struct.pack(">HHHIH", 0xC00C, T_A, 1, 60, 4) + b"\0" * 4, 1)
    if qtype == T_AAAA:
        return _response(query, qend, 0, struct.pack(">HHHIH", 0xC00C, T_AAAA, 1, 60, 16) + b"\0" * 16, 1)
    return _response(query, qend, 0)


def address_response(query: bytes, qtype: int, qend: int, addresses: List[bytes], ttl: int = 300) -> bytes:
    rrs = b"".join(struct.pack(">HHHIH", 0xC00C, qtype, 1, ttl, len(a)) + a for a in addresses)
    return _response(query, qend, 0, rrs, len(addresses))


def servfail(query: bytes, qend: int) -> bytes:
    return _response(query, qend, 2)


def _answers(data: bytes):
    """Iteriert über die Antwort-Einträge: (Typ, TTL, rdata)."""
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    for _ in range(an):
        _, off = _read_name(data, off)
        rtype, _, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        yield rtype, ttl, data[off:off + rdlen]
        off += rdlen


def min_ttl(data: bytes) -> int:
    try:
        ttls = [ttl for _, ttl, _ in _answers(data)]
    except Exception:
        return 0
    return min(ttls) if ttls else 60


def build_query(name: str, qtype: int) -> bytes:
    qid = random.randint(0, 0xFFFF)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)


def is_private_reverse(name: str) -> bool:
    if name.endswith(".ip6.arpa"):
        return True
    if not name.endswith(".in-addr.arpa"):
        return False
    parts = name[:-len(".in-addr.arpa")].split(".")[::-1]
    try:
        return ipaddress.ip_address(".".join((parts + ["0"] * 4)[:4])).is_private
    except ValueError:
        return False


# --- Filter --------------------------------------------------------------------

class DnsFilter:
    def __init__(self, data_dir: Path, port: int, router_host_getter):
        self.dir = data_dir / "filter"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.port = port
        self.router_host = router_host_getter
        self.settings_file = self.dir / "settings.json"
        self.stats_file = self.dir / "stats.json"
        self.settings = {
            "enabled": True, "categories": {k: v["default"] for k, v in CATEGORIES.items()},
            "strict": False, "safeSearch": False, "upstream": "quad9",
            "allow": [], "block": [], "pausedUntil": None,
        }
        if self.settings_file.exists():
            try:
                saved = json.loads(self.settings_file.read_text())
                saved_cats = saved.pop("categories", {})
                self.settings.update(saved)
                self.settings["categories"].update({k: v for k, v in saved_cats.items() if k in CATEGORIES})
            except Exception:
                pass
        self.lists: Dict[str, Set[str]] = {}
        self.list_sizes: Dict[str, int] = {}
        self.lists_updated: Optional[str] = None
        self.cache: Dict[Tuple[str, int], Tuple[bytes, float]] = {}
        self.available = False
        self.bound = ""
        # Wird vom Spike-Wächter gesetzt: bekommt jede Anfrage (Gerät, Name, Antwortcode, Kategorie)
        self.observer = None
        self.problem: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None
        self._transports = []
        self._servers = []
        self._tasks = []
        self._load_stats()

    # --- Einstellungen ---------------------------------------------------------
    def save_settings(self) -> None:
        tmp = self.settings_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.settings, indent=2))
        tmp.replace(self.settings_file)

    @property
    def paused(self) -> bool:
        until = self.settings.get("pausedUntil")
        return bool(until) and until > time.time()

    @property
    def active(self) -> bool:
        return self.settings["enabled"] and not self.paused

    def update(self, body: dict) -> None:
        s = self.settings
        if "enabled" in body:
            s["enabled"] = bool(body["enabled"])
            s["pausedUntil"] = None
        if "pauseMinutes" in body:
            minutes = int(body["pauseMinutes"] or 0)
            s["pausedUntil"] = time.time() + minutes * 60 if minutes > 0 else None
        reload = False
        for key, value in (body.get("categories") or {}).items():
            if key in CATEGORIES and s["categories"].get(key) != bool(value):
                s["categories"][key] = bool(value)
                reload = True
        if "strict" in body and bool(body["strict"]) != s["strict"]:
            s["strict"] = bool(body["strict"])
            reload = True
        if "safeSearch" in body:
            s["safeSearch"] = bool(body["safeSearch"])
            self.cache.clear()
        if body.get("upstream") in UPSTREAMS:
            s["upstream"] = body["upstream"]
            self.cache.clear()
        self.save_settings()
        if reload:
            self._tasks.append(asyncio.ensure_future(self.load_lists(download=True)))

    def set_domain(self, domain: str, list_name: str, add: bool) -> None:
        domain = domain.strip().lower().strip(".")
        if not re.fullmatch(r"[a-z0-9*_.-]{1,253}", domain) or "." not in domain:
            raise ValueError("Das ist keine gültige Adresse.")
        domain = domain.lstrip("*.")
        other = "block" if list_name == "allow" else "allow"
        entries = self.settings[list_name]
        if add:
            if domain not in entries:
                entries.append(domain)
            if domain in self.settings[other]:
                self.settings[other].remove(domain)
        elif domain in entries:
            entries.remove(domain)
        self.cache.clear()
        self.save_settings()

    # --- Blocklisten -----------------------------------------------------------
    def _list_names(self) -> Dict[str, List[str]]:
        names = {}
        for key, cat in CATEGORIES.items():
            if self.settings["categories"].get(key):
                names[key] = cat["strict"] if self.settings["strict"] and "strict" in cat else cat.get("lists", [])
        return names

    async def load_lists(self, download: bool = False) -> None:
        wanted = self._list_names()
        loaded: Dict[str, Set[str]] = {}
        loop = asyncio.get_running_loop()
        for key, names in wanted.items():
            domains: Set[str] = set(CATEGORIES[key].get("builtin", []))
            for name in names:
                path = self.dir / f"{name}.txt"
                fresh = path.exists() and time.time() - path.stat().st_mtime < 20 * 3600
                if (download or not path.exists()) and not fresh:
                    await self._download(name, path)
                if path.exists():
                    domains |= await loop.run_in_executor(None, self._read_list, path)
            excepted = tuple(CATEGORIES[key].get("except", []))
            if excepted:
                dotted = tuple("." + e for e in excepted)
                domains = {d for d in domains if d not in excepted and not d.endswith(dotted)}
            if domains:
                loaded[key] = domains
        self.lists = loaded
        self.list_sizes = {k: len(v) for k, v in loaded.items()}
        files = [self.dir / f"{n}.txt" for ns in wanted.values() for n in ns]
        stamps = [f.stat().st_mtime for f in files if f.exists()]
        if stamps:
            self.lists_updated = datetime.fromtimestamp(min(stamps), timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.cache.clear()
        total = sum(self.list_sizes.values())
        print(f"[spike] Schutzfilter: {total:,} Einträge in {len(loaded)} Kategorien geladen".replace(",", "."), flush=True)
        self._cleanup_files(wanted)

    def _cleanup_files(self, wanted: Dict[str, List[str]]) -> None:
        """Nicht mehr benötigte Listen löschen (z. B. nach dem Wechsel auf größere Listen)."""
        keep = {f"{n}.txt" for ns in wanted.values() for n in ns}
        for f in self.dir.glob("*.txt"):
            if f.name not in keep:
                try:
                    f.unlink()
                except OSError:
                    pass

    async def _download(self, name: str, path: Path) -> None:
        url = f"{LIST_BASE}{name}-onlydomains.txt"
        try:
            async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
                r = await client.get(url)
                r.raise_for_status()
                if len(r.content) < 1000:
                    raise ValueError("Liste ist leer")
            tmp = path.with_suffix(".part")
            tmp.write_bytes(r.content)
            tmp.replace(path)
        except Exception as exc:
            print(f"[spike] Blockliste {name} konnte nicht geladen werden: {exc}", flush=True)

    @staticmethod
    def _read_list(path: Path) -> Set[str]:
        out = set()
        with path.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    out.add(line.lstrip("*."))
        return out

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(6 * 3600)
            await self.load_lists(download=True)

    # --- Entscheidung ------------------------------------------------------------
    @staticmethod
    def _suffixes(name: str):
        parts = name.split(".")
        for i in range(len(parts) - 1):
            yield ".".join(parts[i:])

    def verdict(self, name: str) -> Optional[str]:
        """Kategorie, wenn die Adresse blockiert wird, sonst None."""
        if not self.active:
            return None
        allow, block = self.settings["allow"], self.settings["block"]
        suffixes = list(self._suffixes(name))
        if allow and any(s in allow for s in suffixes):
            return None
        if block and any(s in block for s in suffixes):
            return "custom"
        # Gefahren zuerst, damit der Wächter sie als solche erkennt
        for key in sorted(self.lists, key=lambda k: k != "threats"):
            domains = self.lists[key]
            for s in suffixes:
                if s in domains:
                    return key
        return None

    def safesearch_target(self, name: str) -> Optional[str]:
        if not (self.active and self.settings["safeSearch"]):
            return None
        for pattern, target in SAFESEARCH:
            if pattern.match(name):
                return target
        return None

    # --- Weiterleiten ------------------------------------------------------------
    async def _doh(self, url: str, query: bytes, timeout: float) -> bytes:
        r = await asyncio.wait_for(self.client.post(url, content=query, headers={
            "Content-Type": "application/dns-message", "Accept": "application/dns-message"}), timeout)
        if r.status_code != 200 or len(r.content) < 12:
            raise ConnectionError(f"HTTP {r.status_code}")
        return r.content

    async def forward(self, query: bytes) -> bytes:
        """Verschlüsselt beim gewählten Anbieter nachfragen. Antwortet der nicht schnell, fragt Spike
        gleichzeitig mehrere Ausweichserver und nimmt die erste Antwort. So hängt keine Seite."""
        primary = UPSTREAMS[self.settings["upstream"]]
        try:
            return await self._doh(primary[0], query, 1.5)
        except Exception:
            pass
        others = [u for k, v in UPSTREAMS.items() if k != self.settings["upstream"] for u in v[:1]]
        tasks = [asyncio.ensure_future(self._doh(u, query, 2.5)) for u in [primary[1]] + others]
        tasks += [asyncio.ensure_future(self._udp(query, ip, 53, timeout=2.5)) for ip in PLAIN_FALLBACK]
        try:
            for fut in asyncio.as_completed(tasks, timeout=3):
                try:
                    return await fut
                except Exception:
                    continue
        except asyncio.TimeoutError:
            pass
        finally:
            for t in tasks:
                t.cancel()
        raise ConnectionError("Kein DNS-Server erreichbar")

    async def _udp(self, query: bytes, host: str, port: int, timeout: float = 3) -> bytes:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        class Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not fut.done():
                    fut.set_result(data)

            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)

        transport, _ = await loop.create_datagram_endpoint(Proto, remote_addr=(host, port))
        try:
            transport.sendto(query)
            return await asyncio.wait_for(fut, timeout)
        finally:
            transport.close()

    async def resolve(self, query: bytes, client: str) -> bytes:
        parsed = parse_query(query)
        if parsed is None:
            return query[:2] + struct.pack(">H", 0x8001) + query[4:12] if len(query) >= 12 else b""
        name, qtype, qend = parsed
        self._count(client, name)

        # Namen aus dem Heimnetz kennt nur der Router
        if "." not in name or name.endswith(LOCAL_SUFFIXES) or is_private_reverse(name):
            try:
                return await self._udp(query, self.router_host(), 53, timeout=2)
            except Exception:
                return servfail(query, qend)

        category = self.verdict(name)
        if category:
            self._blocked(client, name, category)
            self._observe(client, name, 0, category)
            if CATEGORIES.get(category, {}).get("nxdomain"):
                # Browser und iCloud Privat-Relay erkennen „gibt es nicht“ als Zeichen, den Filter zu respektieren
                return _response(query, qend, 3)
            return blocked_response(query, qtype, qend)

        target = self.safesearch_target(name)
        if target:
            if qtype not in (T_A, T_AAAA):
                return _response(query, qend, 0)
            try:
                upstream = await self.forward(build_query(target, qtype))
                addrs = [rdata for rtype, _, rdata in _answers(upstream) if rtype == qtype]
                return address_response(query, qtype, qend, addrs)
            except Exception:
                return servfail(query, qend)

        key = (name, qtype)
        cached = self.cache.get(key)
        if cached and cached[1] > time.time():
            self._observe(client, name, cached[0][3] & 0x0F, None)
            return _with_question(query, qend, cached[0])
        try:
            answer = await self.forward(query)
        except Exception:
            if cached:      # Internet kurz weg: lieber die letzte bekannte Antwort als gar keine
                return _with_question(query, qend, cached[0])
            return servfail(query, qend)
        rcode = answer[3] & 0x0F
        self._observe(client, name, rcode, None)
        ttl = max(10, min(3600, min_ttl(answer))) if rcode == 0 else 30
        if len(self.cache) > 20000:
            self.cache.clear()
        self.cache[key] = (answer, time.time() + ttl)
        return answer

    def _observe(self, client: str, name: str, rcode: int, category: Optional[str]) -> None:
        if self.observer:
            try:
                self.observer(client, name, rcode, category)
            except Exception as exc:
                print(f"[spike] Wächter-Fehler: {exc}", flush=True)

    async def health(self) -> dict:
        """Prüft, ob die verschlüsselte Weiterleitung antwortet (für den Wächter)."""
        if not self.available:
            return {"id": "dns", "title": "Namensauflösung", "ok": False,
                    "detail": self.problem or "Der Schutzfilter läuft nicht."}
        start = time.time()
        try:
            answer = await self.forward(build_query("example.com", T_A))
            ok = (answer[3] & 0x0F) == 0
        except Exception:
            ok = False
        ms = int((time.time() - start) * 1000)
        name = {"quad9": "Quad9", "cloudflare": "Cloudflare", "google": "Google"}.get(self.settings["upstream"], "DNS")
        return {"id": "dns", "title": "Verschlüsselte Namensauflösung", "ok": ok,
                "detail": f"{name} antwortet in {ms} ms." if ok else "Keine Antwort vom DNS-Anbieter. Spike versucht es über Ausweichserver."}

    # --- Statistik ---------------------------------------------------------------
    def _load_stats(self) -> None:
        self.day = datetime.now().strftime("%Y-%m-%d")
        self.queries = 0
        self.blocked = 0
        self.top: Counter = Counter()
        self.top_category: Dict[str, str] = {}
        self.client_queries: Counter = Counter()
        self.client_blocked: Counter = Counter()
        self.recent: deque = deque(maxlen=40)
        self.client_last_seen: Dict[str, float] = {}
        if self.stats_file.exists():
            try:
                s = json.loads(self.stats_file.read_text())
                if s.get("day") == self.day:
                    self.queries, self.blocked = s["queries"], s["blocked"]
                    self.top = Counter(s.get("top", {}))
                    self.top_category = s.get("topCategory", {})
                    self.client_queries = Counter(s.get("clientQueries", {}))
                    self.client_blocked = Counter(s.get("clientBlocked", {}))
                self.recent = deque(s.get("recent", []), maxlen=40)
                self.client_last_seen = s.get("clientLastSeen", {})
            except Exception:
                pass

    def save_stats(self) -> None:
        if len(self.top) > 3000:
            self.top = Counter(dict(self.top.most_common(500)))
        tmp = self.stats_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "day": self.day, "queries": self.queries, "blocked": self.blocked, "top": dict(self.top),
            "topCategory": {d: self.top_category.get(d, "ads") for d in self.top},
            "clientQueries": dict(self.client_queries), "clientBlocked": dict(self.client_blocked),
            "recent": list(self.recent), "clientLastSeen": self.client_last_seen,
        }))
        tmp.replace(self.stats_file)

    def _roll_day(self) -> None:
        today = datetime.now().strftime("%Y-%m-%d")
        if today != self.day:
            self.day, self.queries, self.blocked = today, 0, 0
            self.top.clear()
            self.client_queries.clear()
            self.client_blocked.clear()

    def _count(self, client: str, name: str) -> None:
        self._roll_day()
        self.queries += 1
        self.client_queries[client] += 1
        self.client_last_seen[client] = time.time()

    def _blocked(self, client: str, name: str, category: str) -> None:
        self.blocked += 1
        self.top[name] += 1
        self.top_category[name] = category
        self.client_blocked[client] += 1
        if not self.recent or self.recent[0]["domain"] != name or self.recent[0]["client"] != client:
            self.recent.appendleft({"domain": name, "client": client, "date": now_iso(), "category": category})

    def clients_in_use(self, window: float = 3600) -> List[str]:
        limit = time.time() - window
        return [c for c, t in self.client_last_seen.items() if t > limit and not c.startswith("127.")]

    # --- Server ------------------------------------------------------------------
    async def start(self) -> None:
        self.client = httpx.AsyncClient(http2=True, timeout=httpx.Timeout(3.0, connect=2.0),
                                        limits=httpx.Limits(max_connections=20, max_keepalive_connections=6))
        loop = asyncio.get_running_loop()
        dns = self

        class Udp(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                async def answer():
                    try:
                        out = await dns.resolve(data, _client(addr[0]))
                        if out:
                            parsed = parse_query(data)
                            if parsed and len(out) > udp_limit(data, parsed[2]):   # zu groß: Client fragt per TCP neu
                                out = out[:2] + bytes([out[2] | 0x02, out[3]]) + struct.pack(">HHHH", 1, 0, 0, 0) \
                                    + data[12:parsed[2]]
                            self.transport.sendto(out, addr)
                    except Exception as exc:
                        print(f"[spike] DNS-Fehler: {exc}", flush=True)
                asyncio.ensure_future(answer())

        async def tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            peer = _client(writer.get_extra_info("peername")[0])
            try:
                while True:
                    size = struct.unpack(">H", await reader.readexactly(2))[0]
                    data = await reader.readexactly(size)
                    out = await dns.resolve(data, peer)
                    writer.write(struct.pack(">H", len(out)) + out)
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                writer.close()

        # Zuerst auf allen Adressen lauschen. Belegt ein anderer Dienst Port 53 nur auf einer internen Adresse
        # (z. B. 127.0.0.53 bei systemd-resolved oder das Docker-Netz unter Home Assistant OS),
        # weicht Spike auf die Heimnetz-Adresse aus.
        from .discovery import lan_ip
        errors = []
        for host in ("0.0.0.0", lan_ip()):
            try:
                await self._bind(socket.AF_INET, host, Udp, tcp)
                self.bound = host
                break
            except OSError as exc:
                errors.append(f"{host}: {exc}")
                self._close_listeners()
        else:
            self.available = False
            self.problem = (f"Port {self.port} ist auf diesem Gerät schon belegt, wahrscheinlich durch einen anderen "
                            "DNS-Dienst (z. B. AdGuard Home oder Pi-hole). Spike kann den Filter deshalb nicht starten.")
            print(f"[spike] Schutzfilter nicht gestartet: {'; '.join(errors)}", flush=True)
            return
        v6 = lan_ipv6()
        for host in ("::", v6):   # IPv6 zusätzlich, falls vorhanden
            if not host:
                continue
            try:
                await self._bind(socket.AF_INET6, host, Udp, tcp)
                break
            except OSError:
                pass
        self.available = True
        self.problem = None
        print(f"[spike] Schutzfilter lauscht auf {self.bound}:{self.port} (DNS)", flush=True)
        self._tasks.append(asyncio.ensure_future(self._startup_lists()))
        self._tasks.append(asyncio.ensure_future(self._refresh_loop()))
        self._tasks.append(asyncio.ensure_future(self._persist_loop()))

    async def _bind(self, family, host: str, udp_protocol, tcp_handler) -> None:
        loop = asyncio.get_running_loop()
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            sock.bind((host, self.port))
        except OSError:
            sock.close()
            raise
        transport, _ = await loop.create_datagram_endpoint(udp_protocol, sock=sock)
        self._transports.append(transport)
        self._servers.append(await asyncio.start_server(tcp_handler, host, self.port))

    def _close_listeners(self) -> None:
        for t in self._transports:
            t.close()
        for srv in self._servers:
            srv.close()
        self._transports, self._servers = [], []

    async def _startup_lists(self) -> None:
        await self.load_lists(download=False)     # sofort aus dem Zwischenspeicher
        await self.load_lists(download=True)      # dann frisch aus dem Netz

    async def _persist_loop(self) -> None:
        while True:
            await asyncio.sleep(120)
            try:
                self.save_stats()
            except Exception:
                pass

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._transports:
            t.close()
        for s in self._servers:
            s.close()
        try:
            self.save_stats()
        except Exception:
            pass
        if self.client:
            await self.client.aclose()

    # --- Für die App ---------------------------------------------------------------
    def snapshot(self, names: Dict[str, str], server_ip: str, server_ipv6: Optional[str], router_ip: str) -> dict:
        self._roll_day()
        in_use = self.clients_in_use()
        if not self.available:
            status = "unavailable"
        elif not self.settings["enabled"]:
            status = "off"
        elif self.paused:
            status = "paused"
        elif not in_use:
            status = "notConfigured"
        else:
            status = "active"

        def label(ip: str) -> str:
            if ip == router_ip:
                return "Router (alle Geräte)"
            return names.get(ip, ip)

        paused_until = self.settings.get("pausedUntil")
        return {
            "available": self.available,
            "enabled": self.settings["enabled"] and not self.paused,
            "queriesToday": self.queries,
            "blockedToday": self.blocked,
            "topBlocked": [{"domain": d, "count": c, "category": CATEGORY_LABEL.get(self.top_category.get(d, "ads"), "Werbung")}
                           for d, c in self.top.most_common(8)],
            "status": status,
            "problem": self.problem,
            "pausedUntil": datetime.fromtimestamp(paused_until, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            if self.paused else None,
            "serverIP": server_ip,
            "serverIPv6": server_ipv6,
            "routerIsClient": router_ip in in_use,
            "clientsInUse": len(in_use),
            "categories": [{"id": k, "title": c["title"], "detail": c["detail"],
                            "enabled": bool(self.settings["categories"].get(k)), "entries": self.list_sizes.get(k, 0)}
                           for k, c in CATEGORIES.items()],
            "strict": self.settings["strict"],
            "safeSearch": self.settings["safeSearch"],
            "upstream": self.settings["upstream"],
            "allowlist": sorted(self.settings["allow"]),
            "blocklist": sorted(self.settings["block"]),
            "recentBlocked": [{"domain": r["domain"], "client": label(r["client"]), "date": r["date"],
                               "category": CATEGORY_LABEL.get(r["category"], "Werbung")} for r in list(self.recent)[:25]],
            "listsUpdated": self.lists_updated,
        }


def _with_question(query: bytes, qend: int, answer: bytes) -> bytes:
    """Gespeicherte Antwort mit der ID und der Frage (inkl. Groß-/Kleinschreibung) der aktuellen Anfrage.
    Manche Resolver mischen die Schreibweise zufällig und verwerfen Antworten, die nicht exakt passen."""
    try:
        _, aend = _read_name(answer, 12)
        aend += 4
    except ValueError:
        return query[:2] + answer[2:]
    if aend != qend:
        return query[:2] + answer[2:]
    return query[:2] + answer[2:12] + query[12:qend] + answer[qend:]


def udp_limit(query: bytes, qend: int) -> int:
    """Größte Antwort per UDP, die der Fragende annimmt (EDNS), höchstens 4096 Byte."""
    try:
        if struct.unpack(">H", query[10:12])[0] and query[qend] == 0 and \
                struct.unpack(">H", query[qend + 1:qend + 3])[0] == 41:
            return max(512, min(4096, struct.unpack(">H", query[qend + 3:qend + 5])[0]))
    except (IndexError, struct.error):
        pass
    return 512


def _client(ip: str) -> str:
    return ip[7:] if ip.startswith("::ffff:") else ip


def lan_ipv6() -> Optional[str]:
    """Stabile IPv6-Adresse im Heimnetz (ULA fd…), falls vorhanden – für die DNSv6-Einstellung im Router."""
    try:
        with open("/proc/net/if_inet6") as fh:
            for line in fh:
                raw, _, _, scope, flags, _ = line.split()
                addr = ipaddress.ip_address(":".join(raw[i:i + 4] for i in range(0, 32, 4)))
                if addr.version == 6 and str(addr).startswith("fd") and not int(flags, 16) & 0x01:
                    return str(addr)
    except Exception:
        pass
    return None


def dns_port() -> int:
    return int(os.environ.get("SPIKE_DNS_PORT", "53"))
