"""Fragt den DHCP-Server des Routers (DHCPINFORM), welchen DNS-Server er an die Geräte verteilt.

So sieht Spike zuverlässig, ob in der FRITZ!Box „Lokaler DNS-Server“ auf Spike zeigt – genau so, wie es
ein Gerät bei der nächsten Verbindung erfährt. Klappt die Abfrage nicht (z. B. weil Port 68 belegt ist),
ist das Ergebnis „unbekannt“.
"""
from __future__ import annotations

import asyncio
import random
import socket
import struct
import uuid
from typing import List, Optional


def _probe(own_ip: str, router_ip: str, timeout: float = 3.0) -> Optional[List[str]]:
    mac = uuid.getnode().to_bytes(6, "big")
    xid = random.randint(0, 2 ** 32 - 1)
    pkt = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0, socket.inet_aton(own_ip),
                      b"\0" * 4, b"\0" * 4, b"\0" * 4, mac + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    pkt += b"\x63\x82\x53\x63" + bytes([53, 1, 8, 55, 2, 1, 6, 255])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            s.bind(("0.0.0.0", 68))
        except OSError:
            s.bind((own_ip, 68))
        s.settimeout(timeout)
        s.sendto(pkt, (router_ip, 67))
        while True:
            data, _ = s.recvfrom(2048)
            if len(data) < 240 or struct.unpack("!I", data[4:8])[0] != xid:
                continue
            opts, i = data[240:], 0
            while i < len(opts) and opts[i] != 255:
                if opts[i] == 0:
                    i += 1
                    continue
                code, ln = opts[i], opts[i + 1]
                if code == 6:
                    val = opts[i + 2:i + 2 + ln]
                    return [socket.inet_ntoa(val[j:j + 4]) for j in range(0, ln - ln % 4, 4)]
                i += 2 + ln
            return []
    except OSError:
        return None
    finally:
        s.close()


async def lan_dns_servers(own_ip: str, router_ip: str) -> Optional[List[str]]:
    try:
        return await asyncio.get_running_loop().run_in_executor(None, _probe, own_ip, router_ip)
    except Exception:
        return None
