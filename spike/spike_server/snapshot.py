"""Baut das Gesamtbild im Format der App (siehe app/Spike/Model/Models.swift)."""
from __future__ import annotations

from datetime import datetime, timezone

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


async def from_fritzbox(fb, store) -> dict:
    info = await fb.info()
    hosts = await fb.hosts()
    guest = await fb.guest_wifi()
    wps = await fb.wps_active()
    upnp = await fb.upnp_enabled()
    forwards = await fb.port_forward_count()
    remote = await fb.remote_access()
    update = await fb.update_available()

    devices = []
    for h in hosts:
        mac = h.get("MACAddress", "").upper()
        if not mac:
            continue
        known_before = store.is_known(mac)
        meta = store.device(mac)
        name = meta.get("name") or h.get("HostName") or mac
        online = h.get("Active") == "1"
        is_guest = h.get("X_AVM-DE_Guest") == "1"
        if not known_before and online and not is_guest:
            store.log("newDevice", f"Unbekanntes Gerät „{name}“ verbunden")
        iface = h.get("InterfaceType", "")
        devices.append({
            "id": mac, "name": name, "kind": guess_kind(name), "ip": h.get("IPAddress") or None, "mac": mac,
            "vendor": None,
            "connection": "wifi" if iface.startswith("802.11") else ("lan" if iface == "Ethernet" else "unknown"),
            "isOnline": online, "isTrusted": bool(meta.get("trusted")),
            "isBlocked": h.get("X_AVM-DE_WANAccess") == "denied" or h.get("X_AVM-DE_Disallow") == "1",
            "isGuest": is_guest, "firstSeen": meta["first_seen"], "lastSeen": utc_now(),
        })

    checks = []
    fw = info.get("NewSoftwareVersion", "?")
    if update is not None:
        checks.append(check("firmware", "Firmware-Update verfügbar" if update else "Firmware ist aktuell",
                            "Für deinen Router gibt es eine neuere Version mit Sicherheitsupdates. Installiere sie in der Router-Oberfläche."
                            if update else f"Auf deinem Router läuft Version {fw}.",
                            "warning" if update else "ok", "router"))
    if wps is not None:
        checks.append(check("wps", "WPS ist aktiviert" if wps else "WPS ist deaktiviert",
                            "Über WPS kann sich ein Gerät per Knopfdruck ohne Passwort verbinden. Wenn du die Funktion nicht nutzt, solltest du sie deaktivieren."
                            if wps else "Neue Geräte verbinden sich nur mit Passwort oder QR-Code.",
                            "warning" if wps else "ok", "wifi", "WPS deaktivieren" if wps else None))
    if upnp is not None:
        checks.append(check("upnp", "UPnP ist aktiviert" if upnp else "UPnP ist deaktiviert",
                            "Programme in deinem Netzwerk können damit selbstständig Ports zum Internet öffnen. Schadsoftware nutzt genau diese Funktion häufig aus."
                            if upnp else "Kein Programm kann ohne dein Wissen Ports zum Internet öffnen.",
                            "warning" if upnp else "ok", "internet", "UPnP deaktivieren" if upnp else None))
    if forwards is not None:
        checks.append(check("portforwards", f"{forwards} offene Portfreigabe{'n' if forwards != 1 else ''}" if forwards else "Keine offenen Portfreigaben",
                            "Diese Geräte sind direkt aus dem Internet erreichbar. Prüfe in der Router-Oberfläche, ob du sie noch brauchst."
                            if forwards else "Aus dem Internet ist kein Gerät in deinem Netzwerk direkt erreichbar.",
                            "warning" if forwards else "ok", "internet"))
    if remote is not None:
        checks.append(check("remote", "Fernzugriff ist aktiv" if remote else "Kein Fernzugriff aus dem Internet",
                            "Die Router-Oberfläche ist aus dem Internet erreichbar. Sicherer ist der Zugriff nur über VPN."
                            if remote else "Die Router-Oberfläche ist aus dem Internet nicht erreichbar.",
                            "warning" if remote else "ok", "router"))

    snap = {
        "router": {"vendor": "AVM", "model": info.get("NewModelName", "FRITZ!Box"), "firmware": fw,
                   "updateAvailable": bool(update), "uptimeSeconds": int(info.get("NewUpTime", "0") or 0),
                   "capabilities": ALL_CAPABILITIES},
        "devices": devices,
        "guest": {"enabled": guest["enabled"], "ssid": guest["ssid"], "password": guest["password"],
                  "security": "WPA2 + WPA3" if "11i" in guest.get("beacon", "") or "WPA" in guest.get("beacon", "") else "WPA2",
                  "isolated": True},
        "checks": checks,
        "filter": {"available": False, "enabled": False, "queriesToday": 0, "blockedToday": 0, "topBlocked": []},
        "events": store.events(),
        "score": 0,
        "generatedAt": utc_now(),
        "routerConnected": True,
    }
    snap["score"] = compute_score(checks, devices)
    return snap


def empty_snapshot(store) -> dict:
    """Noch kein Router verbunden: leeres Bild, die App zeigt dann „Router verbinden“."""
    return {
        "router": {"vendor": "", "model": "Nicht verbunden", "firmware": "–", "updateAvailable": False,
                   "uptimeSeconds": 0, "capabilities": []},
        "devices": [],
        "guest": {"enabled": False, "ssid": "", "password": "", "security": "", "isolated": True},
        "checks": [],
        "filter": {"available": False, "enabled": False, "queriesToday": 0, "blockedToday": 0, "topBlocked": []},
        "events": store.events(),
        "score": 0,
        "generatedAt": utc_now(),
        "routerConnected": False,
    }
