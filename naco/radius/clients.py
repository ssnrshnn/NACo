"""Which RADIUS client a packet's source address belongs to: the entry for
exactly that address, else the narrowest network entry that contains it."""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from naco.db.models import NasClient


class NasDirectory:
    def __init__(self, clients: Iterable[NasClient]) -> None:
        self._exact: dict[str, NasClient] = {}
        networks = []
        for client in clients:
            if "/" in client.ip_address:
                networks.append((ipaddress.ip_network(client.ip_address), client))
            else:
                self._exact[client.ip_address] = client
        self._networks = sorted(networks, key=lambda item: item[0].prefixlen, reverse=True)

    def find(self, ip: str) -> NasClient | None:
        if (client := self._exact.get(ip)) is not None:
            return client
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, client in self._networks:
            if addr.version == net.version and addr in net:
                return client
        return None


async def nas_directory(db: AsyncSession) -> NasDirectory:
    return NasDirectory((await db.execute(select(NasClient))).scalars())


async def find_nas(db: AsyncSession, ip: str) -> NasClient | None:
    if not ip:
        return None
    exact = (await db.execute(select(NasClient).where(NasClient.ip_address == ip))).scalar_one_or_none()
    if exact is not None:
        return exact
    networks = (await db.execute(select(NasClient).where(NasClient.ip_address.contains("/")))).scalars()
    return NasDirectory(networks).find(ip)
