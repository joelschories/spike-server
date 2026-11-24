"""Meldet den Server per Bonjour (_spike._tcp) im Heimnetz, damit die App ihn findet."""
from __future__ import annotations

import socket

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.168.178.1", 80))  # es wird nichts gesendet, nur die Route bestimmt
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class Announcer:
    def __init__(self, name: str, port: int, server_id: str, version: str, fingerprint: str, mode: str):
        self.ip = lan_ip()
        self.info = AsyncServiceInfo(
            "_spike._tcp.local.",
            f"{name}._spike._tcp.local.",
            addresses=[socket.inet_aton(self.ip)],
            port=port,
            properties={"id": server_id, "version": version, "ip": self.ip, "port": str(port), "fp": fingerprint, "mode": mode},
            server=f"spike-{server_id[:8]}.local.",
        )
        self.zc = AsyncZeroconf(ip_version=IPVersion.V4Only)

    async def start(self) -> None:
        await self.zc.async_register_service(self.info, allow_name_change=True)
        print(f"[spike] Im Heimnetz sichtbar unter {self.ip}:{self.info.port}", flush=True)

    async def stop(self) -> None:
        await self.zc.async_unregister_service(self.info)
        await self.zc.async_close()
