"""FRITZ!Box über die offizielle TR-064-Schnittstelle (SOAP, Digest-Anmeldung)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

import httpx

SOAP_ENV = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
    '<u:{action} xmlns:u="{service}">{args}</u:{action}></s:Body></s:Envelope>'
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class FritzBox:
    def __init__(self, host: str, user: str, password: str):
        self.base = f"http://{host}:49000"
        self.client = httpx.AsyncClient(auth=httpx.DigestAuth(user, password), timeout=10)
        self.control: dict = {}

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

    async def call(self, service: str, action: str, **args) -> dict:
        url = self.base + self.control[service]
        body = SOAP_ENV.format(action=action, service=service,
                               args="".join(f"<{k}>{v}</{k}>" for k, v in args.items()))
        r = await self.client.post(url, content=body.encode(), headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f"{service}#{action}",
        })
        r.raise_for_status()
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
            print(f"[spike] {service}#{action} nicht verfügbar: {exc}", flush=True)
            return None

    # --- Lesen ---------------------------------------------------------------
    async def info(self) -> dict:
        return await self.try_call("urn:dslforum-org:service:DeviceInfo:1", "GetInfo") or {}

    async def hosts(self) -> list:
        res = await self.try_call("urn:dslforum-org:service:Hosts:1", "X_AVM-DE_GetHostListPath")
        if not res:
            return []
        r = await self.client.get(self.base + res["NewX_AVM-DE_HostListPath"])
        hosts = []
        for item in ET.fromstring(r.text).iter("Item"):
            hosts.append({_local(c.tag): (c.text or "") for c in item})
        return hosts

    async def guest_wifi(self) -> dict:
        svc = "urn:dslforum-org:service:WLANConfiguration:3"
        info = await self.try_call(svc, "GetInfo") or {}
        keys = await self.try_call(svc, "GetSecurityKeys") or {}
        return {"enabled": info.get("NewEnable") == "1", "ssid": info.get("NewSSID", ""),
                "password": keys.get("NewKeyPassphrase", ""), "beacon": info.get("NewBeaconType", "")}

    async def wps_active(self) -> Optional[bool]:
        res = await self.try_call("urn:dslforum-org:service:WLANConfiguration:1", "X_AVM-DE_GetWPSInfo")
        if res is None:
            return None
        return res.get("NewX_AVM-DE_WPSStatus", "off") not in ("off", "", "stop")

    async def upnp_enabled(self) -> Optional[bool]:
        res = await self.try_call("urn:dslforum-org:service:X_AVM-DE_UPnP:1", "GetInfo")
        return None if res is None else res.get("NewEnable") == "1"

    async def port_forward_count(self) -> Optional[int]:
        res = await self.try_call("urn:dslforum-org:service:WANIPConnection:1", "GetPortMappingNumberOfEntries")
        return None if res is None else int(res.get("NewPortMappingNumberOfEntries", "0") or 0)

    async def remote_access(self) -> Optional[bool]:
        res = await self.try_call("urn:dslforum-org:service:X_AVM-DE_RemoteAccess:1", "GetInfo")
        return None if res is None else res.get("NewEnabled") == "1"

    async def update_available(self) -> Optional[bool]:
        res = await self.try_call("urn:dslforum-org:service:UserInterface:1", "GetInfo")
        return None if res is None else res.get("NewUpgradeAvailable") == "1"

    # --- Schreiben (nur auf ausdrücklichen Wunsch aus der App) ----------------
    async def set_guest(self, enabled: bool) -> None:
        await self.call("urn:dslforum-org:service:WLANConfiguration:3", "SetEnable", NewEnable=int(enabled))

    async def set_guest_password(self, password: str) -> None:
        await self.call("urn:dslforum-org:service:WLANConfiguration:3", "SetSecurityKeys",
                        NewWEPKey0="", NewWEPKey1="", NewWEPKey2="", NewWEPKey3="",
                        NewPreSharedKey="", NewKeyPassphrase=password)

    async def set_blocked(self, ip: str, blocked: bool) -> None:
        await self.call("urn:dslforum-org:service:X_AVM-DE_HostFilter:1", "DisallowWANAccessByIP",
                        NewIPv4Address=ip, NewDisallow=int(blocked))

    async def disable_wps(self) -> None:
        await self.call("urn:dslforum-org:service:WLANConfiguration:1", "X_AVM-DE_SetWPSConfig",
                        **{"NewX_AVM-DE_WPSMode": "stop", "NewX_AVM-DE_WPSClientPIN": ""})

    async def disable_upnp(self) -> None:
        await self.call("urn:dslforum-org:service:X_AVM-DE_UPnP:1", "SetConfig",
                        NewEnable=0, NewUPnPMediaServer=0)
