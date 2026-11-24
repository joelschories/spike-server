"""Demo-Modus ohne Router-Zugangsdaten: ein Beispielhaushalt, der sich wie ein echtes Netz verhält."""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from .snapshot import ALL_CAPABILITIES, check, compute_score, utc_now


def _ago(minutes: float) -> str:
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return t.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _password() -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))


class Demo:
    def __init__(self, store):
        self.store = store
        day = 60 * 24

        def dev(mac, name, kind, ip, vendor, conn, online=True, trusted=True, guest=False, first=day * 100, last=0):
            return {"id": mac, "name": name, "kind": kind, "ip": ip, "mac": mac, "vendor": vendor, "connection": conn,
                    "isOnline": online, "isTrusted": trusted, "isBlocked": False, "isGuest": guest,
                    "firstSeen": _ago(first), "lastSeen": _ago(last)}

        self.devices = [
            dev("3C:22:FB:10:01:01", "Annas iPhone", "phone", "192.168.178.21", "Apple", "wifi5"),
            dev("3C:22:FB:10:01:02", "MacBook Air", "laptop", "192.168.178.22", "Apple", "wifi6"),
            dev("A4:77:33:20:02:01", "Wohnzimmer-TV", "tv", "192.168.178.30", "LG Electronics", "lan"),
            dev("2C:CF:67:20:02:03", "Spike-Server", "server", "192.168.178.50", "Raspberry Pi", "lan"),
            dev("C8:2B:96:20:02:04", "Steckdose Flur", "plug", "192.168.178.40", "Espressif", "wifi24"),
            dev("D2:41:7A:9E:03:01", "Galaxy-A52", "phone", "192.168.178.57", None, "wifi24", trusted=False, first=6),
            dev("6A:11:0C:44:10:01", "Lenas iPhone", "phone", "192.168.179.20", "Apple", "wifi5", trusted=False, guest=True, first=day * 12),
        ]
        self.guest = {"enabled": True, "ssid": "Spike Gäste", "password": _password(), "security": "WPA2 + WPA3", "isolated": True}
        self.checks = [
            check("firmware", "Firmware ist aktuell", "Auf deinem Router läuft die neueste Version.", "ok", "router"),
            check("wps", "WPS ist aktiviert", "Über WPS kann sich ein Gerät per Knopfdruck ohne Passwort verbinden. Wenn du die Funktion nicht nutzt, solltest du sie deaktivieren.", "warning", "wifi", "WPS deaktivieren"),
            check("upnp", "UPnP ist aktiviert", "Programme in deinem Netzwerk können damit selbstständig Ports zum Internet öffnen. Schadsoftware nutzt genau diese Funktion häufig aus.", "warning", "internet", "UPnP deaktivieren"),
            check("portforwards", "Keine offenen Portfreigaben", "Aus dem Internet ist kein Gerät in deinem Netzwerk direkt erreichbar.", "ok", "internet"),
        ]
        self.filter = {"available": True, "enabled": True, "queriesToday": 18432, "blockedToday": 2317, "topBlocked": [
            {"domain": "app-measurement.com", "count": 412, "category": "Tracking"},
            {"domain": "doubleclick.net", "count": 388, "category": "Werbung"},
            {"domain": "free-prizes.click", "count": 3, "category": "Phishing"},
        ]}

    def snapshot(self) -> dict:
        snap = {
            "router": {"vendor": "AVM", "model": "FRITZ!Box (Demo)", "firmware": "8.25", "updateAvailable": False,
                       "uptimeSeconds": 3 * 86400, "capabilities": ALL_CAPABILITIES},
            "devices": self.devices, "guest": self.guest, "checks": self.checks, "filter": self.filter,
            "events": self.store.events(), "score": 0, "generatedAt": utc_now(), "routerConnected": True,
        }
        snap["score"] = compute_score(self.checks, self.devices)
        return snap

    def set_device(self, id, trusted=None, blocked=None, name=None):
        for d in self.devices:
            if d["id"] == id:
                if trusted is not None:
                    d["isTrusted"] = trusted
                if blocked is not None:
                    d["isBlocked"] = blocked
                if name:
                    d["name"] = name

    def set_guest(self, enabled):
        self.guest["enabled"] = enabled

    def rotate_guest(self):
        self.guest["password"] = _password()

    def fix(self, check_id):
        for c in self.checks:
            if c["id"] == check_id and c["fixLabel"]:
                c.update(status="ok", fixLabel=None,
                         title={"wps": "WPS ist deaktiviert", "upnp": "UPnP ist deaktiviert"}.get(check_id, c["title"]))

    def set_filter(self, enabled):
        self.filter["enabled"] = enabled
