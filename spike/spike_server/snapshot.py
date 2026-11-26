"""Baut das Gesamtbild im Format der App (siehe app/Spike/Model/Models.swift)."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Dict, Optional

ALL_CAPABILITIES = ["deviceList", "deviceBlocking", "guestWifi", "wifiSettings", "securityChecks", "firmwareInfo"]


def guess_kind(name: str) -> str:
    n = name.lower()
    rules = [
        (("iphone", "pixel", "galaxy", "android", "handy", "phone"), "phone"),
        (("ipad", "tab"), "tablet"),
        (("macbook", "laptop", "notebook", "thinkpad"), "laptop"),
        (("imac", "desktop", "pc-", "mac-mini", "macmini"), "desktop"),
        (("watch",), "watch"),
        (("tv", "fernseher", "chromecast", "appletv", "fire"), "tv"),
        (("homepod", "sonos", "echo", "speaker", "lautsprecher"), "speaker"),
        (("playstation", "ps5", "xbox", "switch"), "console"),
        (("cam", "kamera", "ring", "doorbell"), "camera"),
        (("plug", "steckdose", "shelly", "tasmota"), "plug"),
        (("hue", "licht", "lamp", "light", "bulb"), "light"),
        (("roborock", "roomba", "sauger", "vacuum"), "vacuum"),
        (("raspberry", "homeassistant", "nas", "server", "spike"), "server"),
    ]
    for keys, kind in rules:
        if any(k in n for k in keys):
            return kind
    return "unknown"


def compute_score(checks: list, devices: list) -> int:
    score = 100
    for c in checks:
        if c.get("dismissed"):
            continue
        if c["status"] == "critical":
            score -= 25
        elif c["status"] == "warning":
            score -= 8
    score -= 12 * sum(1 for d in devices if d["isOnline"] and not d["isTrusted"] and not d["isGuest"] and not d["isBlocked"])
    return max(0, min(100, score))


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def check(id: str, title: str, detail: str, status: str, category: str, fix: str = None) -> dict:
    return {"id": id, "title": title, "detail": detail, "status": status, "category": category, "fixLabel": fix}


class Overrides:
    """Merkt sich gerade geänderte Werte. Die FRITZ!Box braucht nach einer Änderung (z. B. WLAN an)
    einige Sekunden, bis sie den neuen Zustand meldet. So springt der Schalter in der App nicht zurück."""

    def __init__(self):
        self.values: Dict[str, tuple] = {}

    def set(self, key: str, value, seconds: float = 45) -> None:
        self.values[key] = (value, time.time() + seconds)

    def apply(self, key: str, actual):
        entry = self.values.get(key)
        if entry is None:
            return actual
        value, until = entry
        if actual == value or time.time() > until:
            del self.values[key]
            return actual
        return value


def _security_label(beacon: str) -> str:
    b = beacon.lower()
    if "wpa3" in b and ("11i" in b or "wpa2" in b):
        return "WPA2 + WPA3"
    if "wpa3" in b:
        return "WPA3"
    if "11i" in b or "wpa2" in b or "wpaand11i" in b:
        return "WPA2"
    if b in ("none", "basic"):
        return "Offen"
    return "WPA2"


async def from_fritzbox(fb, store, overrides: Overrides, dns=None, server_ip: str = "", server_ipv6: Optional[str] = None) -> dict:
    # Erst prüfen, ob die Anmeldung klappt: sonst lieber eine klare Fehlermeldung als ein leeres Bild
    await fb.call("urn:dslforum-org:service:Hosts:1", "GetHostNumberOfEntries")
    info = await fb.cached("info", 60, fb.info)
    hosts = await fb.hosts()
    guest = await fb.guest_wifi()
    wps = await fb.wps_active()
    upnp = await fb.upnp()
    internet = await fb.cached("internet", 60, fb.internet)
    forwards = await fb.cached("forwards", 300, fb.port_forwards)
    remote = await fb.cached("remote", 300, fb.remote_access)
    update = await fb.cached("update", 1800, fb.update_info)
    user = await fb.cached("user", 300, fb.current_user)
    two_factor = await fb.cached("2fa", 300, fb.two_factor_enabled)
    wifi = await fb.cached("wifi", 120, fb.wifi)

    devices = []
    names: Dict[str, str] = {}
    for h in hosts:
        mac = h.get("MACAddress", "").upper()
        if not mac:
            continue
        known_before = store.is_known(mac)
        meta = store.device(mac)
        name = meta.get("name") or h.get("HostName") or mac
        online = h.get("Active") == "1"
        if online:
            store.mark_online(mac)
        is_guest = h.get("X_AVM-DE_Guest") == "1"
        if not known_before and online and not is_guest:
            store.log("newDevice", f"Unbekanntes Gerät „{name}“ verbunden")
        iface = h.get("InterfaceType", "")
        ip = h.get("IPAddress") or None
        if ip:
            names[ip] = name
        blocked = h.get("X_AVM-DE_WANAccess") == "denied" or h.get("X_AVM-DE_Disallow") == "1"
        devices.append({
            "id": mac, "name": name, "kind": guess_kind(name), "ip": ip, "mac": mac,
            "vendor": None,
            "connection": "wifi" if iface.startswith("802.11") else ("lan" if iface == "Ethernet" else "unknown"),
            "isOnline": online, "isTrusted": bool(meta.get("trusted")),
            "isBlocked": overrides.apply(f"block:{mac}", blocked),
            "isGuest": is_guest, "firstSeen": meta["first_seen"],
            # Zuletzt online: jetzt, oder der Zeitpunkt, an dem Spike das Gerät zuletzt online gesehen hat
            "lastSeen": utc_now() if online else meta.get("last_online"),
        })

    if wps is not None:
        wps = overrides.apply("wps", wps)
    upnp_on = overrides.apply("upnp", upnp["enabled"]) if upnp else None
    guest_on = overrides.apply("guest", guest["enabled"])

    checks = []
    fw = info.get("NewSoftwareVersion", "?")
    update_available = bool(update and update["available"])
    if user.get("canWrite") is False:
        checks.append(check("rights", "Spike darf nichts ändern",
                            f"Der FRITZ!Box-Benutzer „{user.get('name') or 'Spike'}“ hat nur Leserechte. Damit Spike Gast-WLAN, "
                            "WPS oder Sperren schalten kann, braucht er das Recht „FRITZ!Box Einstellungen“ "
                            "(FRITZ!Box › System › FRITZ!Box-Benutzer).", "warning", "router"))
    if update is not None:
        checks.append(check("firmware", "Firmware-Update verfügbar" if update_available else "Firmware ist aktuell",
                            f"Für deinen Router gibt es FRITZ!OS {update['version']} mit Verbesserungen und Sicherheitsupdates. "
                            "Installiere es in der FRITZ!Box unter System › Update." if update_available
                            else f"Auf deinem Router läuft FRITZ!OS {fw}.",
                            "warning" if update_available else "ok", "router"))
    if wps is not None:
        checks.append(check("wps", "WPS ist aktiviert" if wps else "WPS ist deaktiviert",
                            "Über WPS kann sich ein Gerät per Knopfdruck ohne Passwort verbinden. Wenn du die Funktion nicht nutzt, solltest du sie deaktivieren."
                            if wps else "Neue Geräte verbinden sich nur mit Passwort oder QR-Code.",
                            "warning" if wps else "ok", "wifi", "WPS deaktivieren" if wps else None))
    if upnp_on is not None:
        checks.append(check("upnp", "UPnP ist aktiviert" if upnp_on else "UPnP ist deaktiviert",
                            "Programme in deinem Netzwerk können damit selbstständig Ports zum Internet öffnen. Schadsoftware nutzt genau diese Funktion häufig aus. "
                            "Spielekonsolen brauchen sie manchmal für Online-Spiele." if upnp_on
                            else "Kein Programm kann ohne dein Wissen Ports zum Internet öffnen.",
                            "warning" if upnp_on else "ok", "internet", "UPnP deaktivieren" if upnp_on else None))
    if forwards is not None:
        n = len(forwards)
        lines = "\n".join(f"• Port {f['port']}/{f['protocol']} → {names.get(f['client'], f['client'])}"
                          f"{' (' + f['description'] + ')' if f['description'] else ''}" for f in forwards[:8])
        checks.append(check("portforwards", f"{n} offene Portfreigabe{'n' if n != 1 else ''}" if n else "Keine offenen Portfreigaben",
                            f"Diese Geräte sind direkt aus dem Internet erreichbar:\n{lines}\nPrüfe in der FRITZ!Box unter Internet › Freigaben, ob du sie noch brauchst."
                            if n else "Aus dem Internet ist kein Gerät in deinem Netzwerk direkt erreichbar.",
                            "warning" if n else "ok", "internet"))
    if remote is not None:
        checks.append(check("remote", "Fernzugriff ist aktiv" if remote else "Kein Fernzugriff aus dem Internet",
                            "Die Router-Oberfläche ist aus dem Internet erreichbar. Sicherer ist der Zugriff nur über VPN."
                            if remote else "Die Router-Oberfläche ist aus dem Internet nicht erreichbar.",
                            "warning" if remote else "ok", "router"))
    for w in wifi:
        sec = _security_label(w["beacon"])
        if sec == "Offen":
            checks.append(check(f"wifi{w['index']}", f"WLAN „{w['ssid']}“ ist offen",
                                "Jeder in Reichweite kann sich ohne Passwort verbinden. Stelle die Verschlüsselung auf WPA2 oder WPA3 um.",
                                "critical", "wifi"))
    if wifi:
        best = max(wifi, key=lambda w: "wpa3" in w["beacon"].lower())
        checks.append(check("encryption", f"WLAN verschlüsselt mit {_security_label(best['beacon'])}",
                            "Dein Heimnetz-WLAN ist mit einem Passwort geschützt.", "ok", "wifi"))

    filter_snap = None
    if dns is not None:
        filter_snap = dns.snapshot(names, server_ip, server_ipv6, fb.host)
        if filter_snap["status"] == "notConfigured":
            checks.append(check("filter", "Schutzfilter ist noch nicht eingerichtet",
                                "Spike kann Werbung, Tracker und gefährliche Seiten für alle Geräte blockieren. "
                                "Dafür trägst du Spike einmal als DNS-Server in deiner FRITZ!Box ein.", "info", "internet"))

    snap = {
        "router": {"vendor": "AVM", "model": info.get("NewModelName", "FRITZ!Box"), "firmware": fw,
                   "updateAvailable": update_available, "uptimeSeconds": int(info.get("NewUpTime", "0") or 0),
                   "capabilities": ALL_CAPABILITIES,
                   "latestFirmware": update["version"] if update_available else None,
                   "internet": internet,
                   "user": user.get("name") or None,
                   "canWrite": user.get("canWrite"),
                   "twoFactor": two_factor,
                   "wps": wps, "upnp": upnp_on,
                   "wifi": [{"ssid": w["ssid"], "band": w["band"], "enabled": w["enabled"],
                             "channel": w["channel"], "security": _security_label(w["beacon"])} for w in wifi]},
        "devices": devices,
        "guest": {"enabled": guest_on, "ssid": guest["ssid"], "password": guest["password"],
                  "security": _security_label(guest.get("beacon", "")),
                  "isolated": guest.get("isolated", True),
                  "hidden": False,
                  "configured": bool(guest["ssid"] and guest["password"]),
                  "supported": guest.get("supported", True)},
        "checks": checks,
        "filter": filter_snap or empty_filter(),
        "events": store.events(),
        "score": 0,
        "generatedAt": utc_now(),
        "routerConnected": True,
    }
    snap["score"] = compute_score(checks, devices)
    return snap


def empty_filter() -> dict:
    return {"available": False, "enabled": False, "queriesToday": 0, "blockedToday": 0, "topBlocked": []}


def empty_snapshot(store, dns=None, server_ip: str = "", server_ipv6: Optional[str] = None, router_ip: str = "") -> dict:
    """Noch kein Router verbunden: leeres Bild, die App zeigt dann „Router verbinden“."""
    return {
        "router": {"vendor": "", "model": "Nicht verbunden", "firmware": "–", "updateAvailable": False,
                   "uptimeSeconds": 0, "capabilities": []},
        "devices": [],
        "guest": {"enabled": False, "ssid": "", "password": "", "security": "", "isolated": True},
        "checks": [],
        "filter": dns.snapshot({}, server_ip, server_ipv6, router_ip) if dns else empty_filter(),
        "events": store.events(),
        "score": 0,
        "generatedAt": utc_now(),
        "routerConnected": False,
    }
