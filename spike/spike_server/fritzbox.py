"""FRITZ!Box über die offizielle TR-064-Schnittstelle (SOAP, Digest-Anmeldung).

Änderungen am Router verlangen bei FRITZ!OS ab 7.5 je nach Einstellung eine Bestätigung direkt
an der FRITZ!Box (Zwei-Faktor, Fehler 866). Spike startet sie dann und wiederholt die Aktion,
sobald jemand eine Taste an der Box gedrückt hat (siehe `Confirmations`).
"""
from __future__ import annotations

import asyncio
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional
from xml.sax.saxutils import escape

import httpx

SOAP_ENV = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">{header}<s:Body>'
    '<u:{action} xmlns:u="{service}">{args}</u:{action}></s:Body></s:Envelope>'
)
TOKEN_HEADER = '<s:Header><avm:token xmlns:avm="avm.de" s:mustUnderstand="1">{}</avm:token></s:Header>'

AUTH = "urn:dslforum-org:service:X_AVM-DE_Auth:1"
WLAN = "urn:dslforum-org:service:WLANConfiguration:{}"
HOSTS = "urn:dslforum-org:service:Hosts:1"
UPNP = "urn:dslforum-org:service:X_AVM-DE_UPnP:1"
WANIP = "urn:dslforum-org:service:WANIPConnection:1"
WANPPP = "urn:dslforum-org:service:WANPPPConnection:1"
WANCOMMON = "urn:dslforum-org:service:WANCommonInterfaceConfig:1"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class RouterError(Exception):
    """Fehler der FRITZ!Box mit verständlicher Meldung für die App."""

    MESSAGES = {
        401: "Benutzername oder Passwort für die FRITZ!Box stimmen nicht mehr. Verbinde den Router in den Einstellungen neu.",
        402: "Die FRITZ!Box hat die Anfrage nicht verstanden (ungültige Werte).",
        606: "Dem FRITZ!Box-Benutzer fehlt das Recht „FRITZ!Box Einstellungen“. Du kannst es in der FRITZ!Box unter "
             "System › FRITZ!Box-Benutzer vergeben.",
        501: "Diese Funktion unterstützt dein Router nicht.",
        714: "Diesen Eintrag gibt es in der FRITZ!Box nicht.",
        820: "In der FRITZ!Box ist ein interner Fehler aufgetreten. Versuche es gleich noch einmal.",
        866: "Die FRITZ!Box möchte die Änderung direkt am Gerät bestätigt haben.",
        867: "Es gab zu viele Bestätigungsversuche. Die FRITZ!Box lässt Änderungen erst in bis zu 60 Minuten wieder zu.",
        868: "An der FRITZ!Box läuft gerade schon eine Bestätigung. Versuche es in zwei Minuten noch einmal.",
    }

    def __init__(self, code: int, description: str = ""):
        self.code = code
        self.description = description
        super().__init__(self.MESSAGES.get(code, f"Die FRITZ!Box hat die Änderung abgelehnt (Fehler {code}"
                                                 f"{': ' + description if description else ''})."))


class FritzBox:
    def __init__(self, host: str, user: str, password: str):
        self.host = host
        self.base = f"http://{host}:49000"
        self.client = httpx.AsyncClient(auth=httpx.DigestAuth(user, password), timeout=12)
        self.control: Dict[str, str] = {}
        # Die FRITZ!Box verträgt keine parallelen Digest-Anmeldungen (Nonce-Zähler) und sperrt den Zugang
        # nach mehreren Fehlversuchen kurz. Deshalb geht immer nur eine Anfrage gleichzeitig hinaus.
        self.lock = asyncio.Lock()
        self._cache: Dict[str, tuple] = {}

    async def cached(self, key: str, seconds: float, fetch):
        """Selten wechselnde Werte (Rechte, Update, Portfreigaben …) nur alle paar Minuten abfragen."""
        hit = self._cache.get(key)
        if hit and hit[1] > time.time():
            return hit[0]
        value = await fetch()
        self._cache[key] = (value, time.time() + seconds)
        return value

    async def connect(self) -> None:
        """Liest die Dienstbeschreibung, um die Steuer-URLs zu kennen."""
        r = await self.client.get(f"{self.base}/tr64desc.xml")
        r.raise_for_status()
        root = ET.fromstring(r.text)
        for el in root.iter():
            if _local(el.tag) == "service":
                fields = {_local(c.tag): (c.text or "") for c in el}
                self.control[fields.get("serviceType", "")] = fields.get("controlURL", "")

    def has(self, service: str) -> bool:
        return service in self.control

    async def call(self, service: str, action: str, token: Optional[str] = None, **args) -> dict:
        if not self.has(service):
            raise RouterError(501, action)
        url = self.base + self.control[service]
        body = SOAP_ENV.format(header=TOKEN_HEADER.format(token) if token else "", action=action, service=service,
                               args="".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in args.items()))
        try:
            async with self.lock:
                r = await self.client.post(url, content=body.encode(), headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPAction": f"{service}#{action}",
                })
        except httpx.HTTPError as exc:
            raise ConnectionError(f"FRITZ!Box nicht erreichbar: {exc}") from exc
        if r.status_code == 401:
            raise RouterError(401)
        if r.status_code >= 400:
            code, desc = 0, ""
            try:
                for el in ET.fromstring(r.text).iter():
                    if _local(el.tag) == "errorCode":
                        code = int(el.text or 0)
                    elif _local(el.tag) == "errorDescription":
                        desc = el.text or ""
            except ET.ParseError:
                pass
            raise RouterError(code or r.status_code, desc)
        out: dict = {}
        for el in ET.fromstring(r.text).iter():
            if _local(el.tag).startswith("New"):
                out[_local(el.tag)] = el.text or ""
        return out

    async def try_call(self, service: str, action: str, **args) -> Optional[dict]:
        if not self.has(service):
            return None
        try:
            return await self.call(service, action, **args)
        except Exception as exc:  # einzelne Funktionen fehlen je nach Modell/Rechten
            print(f"[spike] {service.rsplit(':', 2)[-2]}#{action} nicht verfügbar: {exc}", flush=True)
            return None

    # --- Lesen ---------------------------------------------------------------
    async def info(self) -> dict:
        return await self.try_call("urn:dslforum-org:service:DeviceInfo:1", "GetInfo") or {}

    async def hosts(self) -> list:
        res = await self.try_call(HOSTS, "X_AVM-DE_GetHostListPath")
        if not res:
            return []
        async with self.lock:
            r = await self.client.get(self.base + res["NewX_AVM-DE_HostListPath"])
        r.raise_for_status()
        hosts = []
        for item in ET.fromstring(r.text).iter("Item"):
            hosts.append({_local(c.tag): (c.text or "") for c in item})
        return hosts

    def wlan_indexes(self) -> List[int]:
        return sorted(int(s.rsplit(":", 1)[1]) for s in self.control if s.startswith(WLAN.format("")))

    @property
    def guest_index(self) -> Optional[int]:
        """Das Gast-WLAN ist bei FRITZ!Boxen immer die letzte WLAN-Konfiguration (ab drei vorhandenen)."""
        idx = self.wlan_indexes()
        return idx[-1] if len(idx) >= 3 else None

    @property
    def home_wlans(self) -> List[int]:
        g = self.guest_index
        return [i for i in self.wlan_indexes() if i != g]

    async def guest_wifi(self) -> dict:
        if self.guest_index is None:
            return {"enabled": False, "ssid": "", "password": "", "beacon": "", "supported": False}
        svc = WLAN.format(self.guest_index)
        info = await self.try_call(svc, "GetInfo") or {}
        keys = await self.try_call(svc, "GetSecurityKeys") or {}
        ext = await self.try_call(svc, "X_AVM-DE_GetWLANExtInfo") or {}
        beacon = await self.try_call(svc, "GetBeaconAdvertisement") or {}
        return {"enabled": info.get("NewEnable") == "1", "ssid": info.get("NewSSID", ""),
                "password": keys.get("NewKeyPassphrase", ""), "beacon": info.get("NewBeaconType", ""),
                "isolated": ext.get("NewX_AVM-DE_UserIsolation", "1") != "0", "supported": True,
                "hidden": beacon.get("NewBeaconAdvertisementEnabled", "1") == "0"}

    async def wifi(self) -> List[dict]:
        out = []
        for i in self.home_wlans:
            info = await self.try_call(WLAN.format(i), "GetInfo")
            if info:
                out.append({"index": i, "enabled": info.get("NewEnable") == "1", "ssid": info.get("NewSSID", ""),
                            "band": info.get("NewX_AVM-DE_FrequencyBand", ""), "channel": info.get("NewChannel", ""),
                            "beacon": info.get("NewBeaconType", ""), "standard": info.get("NewStandard", "")})
        return out

    async def wps_active(self) -> Optional[bool]:
        states = []
        for i in self.home_wlans:
            res = await self.try_call(WLAN.format(i), "X_AVM-DE_GetWPSInfo")
            if res is not None:
                states.append(res.get("NewX_AVM-DE_WPSStatus", "off") not in ("off", ""))
        return any(states) if states else None

    async def upnp(self) -> Optional[dict]:
        res = await self.try_call(UPNP, "GetInfo")
        if res is None:
            return None
        return {"enabled": res.get("NewEnable") == "1", "media": res.get("NewUPnPMediaServer") == "1"}

    def wan_service(self) -> str:
        return WANIP if self.has(WANIP) else WANPPP

    async def port_forwards(self) -> Optional[List[dict]]:
        svc = self.wan_service()
        res = await self.try_call(svc, "GetPortMappingNumberOfEntries")
        if res is None:
            return None
        out = []
        for i in range(min(int(res.get("NewPortMappingNumberOfEntries", "0") or 0), 30)):
            entry = await self.try_call(svc, "GetGenericPortMappingEntry", NewPortMappingIndex=i)
            if entry and entry.get("NewEnabled") == "1":
                out.append({"port": entry.get("NewExternalPort", ""), "protocol": entry.get("NewProtocol", ""),
                            "client": entry.get("NewInternalClient", ""),
                            "description": entry.get("NewPortMappingDescription", "")})
        return out

    async def remote_access(self) -> Optional[bool]:
        res = await self.try_call("urn:dslforum-org:service:X_AVM-DE_RemoteAccess:1", "GetInfo")
        return None if res is None else res.get("NewEnabled") == "1"

    async def update_info(self) -> Optional[dict]:
        res = await self.try_call("urn:dslforum-org:service:UserInterface:1", "GetInfo")
        if res is None:
            return None
        return {"available": res.get("NewUpgradeAvailable") == "1", "version": res.get("NewX_AVM-DE_Version", "")}

    async def internet(self) -> dict:
        status = await self.try_call(self.wan_service(), "GetStatusInfo") or {}
        link = await self.try_call(WANCOMMON, "GetCommonLinkProperties") or {}

        def mbit(v: str) -> int:
            try:
                return int(int(v) / 1_000_000)
            except (TypeError, ValueError):
                return 0
        return {"online": status.get("NewConnectionStatus") == "Connected",
                "uptimeSeconds": int(status.get("NewUptime", "0") or 0),
                "downstreamMbit": mbit(link.get("NewX_AVM-DE_DownstreamCurrentMaxSpeed") or link.get("NewLayer1DownstreamMaxBitRate")),
                "upstreamMbit": mbit(link.get("NewX_AVM-DE_UpstreamCurrentMaxSpeed") or link.get("NewLayer1UpstreamMaxBitRate")),
                "accessType": link.get("NewWANAccessType", "")}

    async def current_user(self) -> dict:
        """Name und Rechte des Benutzers, mit dem Spike angemeldet ist."""
        res = await self.try_call("urn:dslforum-org:service:LANConfigSecurity:1", "X_AVM-DE_GetCurrentUser")
        if not res:
            return {"name": "", "canWrite": None}
        rights: Dict[str, str] = {}
        try:
            root = ET.fromstring(res.get("NewX_AVM-DE_CurrentUserRights", "") or "<rights/>")
            path = None
            for el in root.iter():
                if _local(el.tag) == "path":
                    path = el.text
                elif _local(el.tag) == "access" and path:
                    rights[path] = el.text or ""
        except ET.ParseError:
            pass
        can_write = rights.get("BoxAdmin") == "readwrite" if rights else None
        return {"name": res.get("NewX_AVM-DE_CurrentUsername", ""), "canWrite": can_write}

    async def two_factor_enabled(self) -> Optional[bool]:
        res = await self.try_call(AUTH, "GetInfo")
        return None if res is None else res.get("NewEnabled") == "1"

    # --- Schreiben (nur auf ausdrücklichen Wunsch aus der App) ----------------
    # Jede Methode nimmt ein optionales Bestätigungs-Token (Zwei-Faktor) entgegen.
    async def set_guest(self, enabled: bool, token: Optional[str] = None) -> None:
        await self.call(WLAN.format(self.guest_index), "SetEnable", token=token, NewEnable=int(enabled))

    async def set_guest_password(self, password: str, token: Optional[str] = None) -> None:
        await self.call(WLAN.format(self.guest_index), "SetSecurityKeys", token=token,
                        NewWEPKey0="", NewWEPKey1="", NewWEPKey2="", NewWEPKey3="",
                        NewPreSharedKey="", NewKeyPassphrase=password)

    async def set_guest_ssid(self, ssid: str, token: Optional[str] = None) -> None:
        await self.call(WLAN.format(self.guest_index), "SetSSID", token=token, NewSSID=ssid)

    async def set_guest_hidden(self, hidden: bool, token: Optional[str] = None) -> None:
        """Gast-WLAN unsichtbar: Der Name erscheint in keiner WLAN-Liste, verbinden geht per QR-Code."""
        await self.call(WLAN.format(self.guest_index), "SetBeaconAdvertisement", token=token,
                        NewBeaconAdvertisementEnabled=int(not hidden))

    async def set_blocked(self, ip: str, blocked: bool, token: Optional[str] = None) -> None:
        await self.call("urn:dslforum-org:service:X_AVM-DE_HostFilter:1", "DisallowWANAccessByIP", token=token,
                        NewIPv4Address=ip, NewDisallow=int(blocked))

    async def set_wps(self, enabled: bool, token: Optional[str] = None) -> None:
        for i in self.home_wlans:
            await self.call(WLAN.format(i), "X_AVM-DE_SetWPSEnable", token=token,
                            **{"NewX_AVM-DE_WPSEnable": int(enabled)})

    async def set_upnp(self, enabled: bool, token: Optional[str] = None) -> None:
        current = await self.upnp() or {"media": False}
        await self.call(UPNP, "SetConfig", token=token, NewEnable=int(enabled), NewUPnPMediaServer=int(current["media"]))

    async def wake(self, mac: str, token: Optional[str] = None) -> None:
        await self.call(HOSTS, "X_AVM-DE_WakeOnLANByMACAddress", token=token, NewMACAddress=mac)

    async def reboot(self, token: Optional[str] = None) -> None:
        await self.call("urn:dslforum-org:service:DeviceConfig:1", "Reboot", token=token)

    async def close(self) -> None:
        await self.client.aclose()


# --- Bestätigung an der FRITZ!Box (Zwei-Faktor) -----------------------------------

@dataclass
class Confirmation:
    id: str
    title: str
    methods: List[str]
    token: str
    action: Callable[[Optional[str]], Awaitable[None]]
    on_done: Optional[Callable[[], None]] = None
    status: str = "waiting"          # waiting | done | failed | expired | cancelled
    message: str = ""
    created: float = field(default_factory=time.time)
    task: Optional[asyncio.Task] = None

    def public(self) -> dict:
        return {"id": self.id, "title": self.title, "methods": self.methods, "status": self.status,
                "message": self.message or None}


class ConfirmationNeeded(Exception):
    def __init__(self, confirmation: Confirmation):
        self.confirmation = confirmation
        super().__init__(confirmation.title)


class Confirmations:
    TIMEOUT = 120

    def __init__(self):
        self.items: Dict[str, Confirmation] = {}

    async def run(self, fb: FritzBox, title: str, action: Callable[[Optional[str]], Awaitable[None]],
                  on_done: Optional[Callable[[], None]] = None) -> None:
        """Führt eine Änderung aus. Verlangt die Box eine Bestätigung, wird `ConfirmationNeeded` ausgelöst."""
        try:
            await action(None)
            if on_done:
                on_done()
            return
        except RouterError as exc:
            if exc.code != 866:
                raise
        start = await fb.call(AUTH, "SetConfig", NewAction="start")
        state, token = start.get("NewState", ""), start.get("NewToken", "")
        if state in ("anotherauthprocess",):
            raise RouterError(868)
        if state == "blocked":
            raise RouterError(867)
        if not token:
            raise RouterError(820)
        methods = [m.strip() for m in start.get("NewMethods", "button").split(",") if m.strip()]
        conf = Confirmation(id=uuid.uuid4().hex[:12], title=title, methods=methods, token=token,
                            action=action, on_done=on_done)
        self._cleanup()
        self.items[conf.id] = conf
        conf.task = asyncio.ensure_future(self._watch(fb, conf))
        raise ConfirmationNeeded(conf)

    async def _watch(self, fb: FritzBox, conf: Confirmation) -> None:
        deadline = time.time() + self.TIMEOUT
        while time.time() < deadline and conf.status == "waiting":
            await asyncio.sleep(1.5)
            try:
                state = (await fb.call(AUTH, "GetState", token=conf.token)).get("NewState", "")
            except Exception:
                continue
            if state == "authenticated":
                try:
                    await conf.action(conf.token)
                    conf.status = "done"
                    if conf.on_done:
                        conf.on_done()
                except Exception as exc:
                    conf.status, conf.message = "failed", str(exc)
                return
            if state in ("stopped", "blocked", "failure", "disabled"):
                conf.status = "failed"
                conf.message = str(RouterError(867)) if state == "blocked" else "Die Bestätigung wurde abgebrochen."
                return
        if conf.status == "waiting":
            conf.status = "expired"
            conf.message = "Die Zeit für die Bestätigung ist abgelaufen."
            try:
                await fb.call(AUTH, "SetConfig", token=conf.token, NewAction="stop")
            except Exception:
                pass

    async def cancel(self, fb: Optional[FritzBox], cid: str) -> None:
        conf = self.items.get(cid)
        if conf and conf.status == "waiting":
            conf.status = "cancelled"
            if conf.task:
                conf.task.cancel()
            if fb:
                try:
                    await fb.call(AUTH, "SetConfig", token=conf.token, NewAction="stop")
                except Exception:
                    pass

    def get(self, cid: str) -> Optional[Confirmation]:
        return self.items.get(cid)

    def _cleanup(self) -> None:
        limit = time.time() - 600
        for cid in [c for c, v in self.items.items() if v.created < limit]:
            del self.items[cid]
