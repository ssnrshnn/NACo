#!/usr/bin/env python3
"""
RADIUS authentication throughput benchmark.

Fires MAB (or PAP) Access-Requests at a RADIUS server from asyncio UDP
sockets and reports auth/s, latency percentiles and the outcome mix.
Works against NACo, FreeRADIUS or anything else speaking RFC 2865.

Examples
--------
    # 30 s, 32 in-flight requests, MAB for a known device
    python bench/radius_bench.py --host 127.0.0.1 --port 1812 \
        --secret testing123 --mac aa:bb:cc:dd:ee:ff --concurrency 32

    # PAP user/password
    python bench/radius_bench.py --secret testing123 \
        --user alice --password s3cret --duration 10

The tool measures *server* throughput: every request waits for its reply
(or times out), so requests-in-flight == --concurrency.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import sys
import time

import pyrad.dictionary
import pyrad.packet

_DICT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "naco", "radius", "dictionary",
)


class _Client(asyncio.DatagramProtocol):
    """One UDP socket multiplexing many outstanding requests by packet id."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.pending: dict[int, asyncio.Future[bytes]] = {}

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) < 2:
            return
        fut = self.pending.pop(data[1], None)
        if fut is not None and not fut.done():
            fut.set_result(data)


async def _worker(
    proto: _Client,
    args: argparse.Namespace,
    dictionary: pyrad.dictionary.Dictionary,
    stop_at: float,
    stats: dict,
    id_pool: list[int],
) -> None:
    secret = args.secret.encode()
    while time.monotonic() < stop_at:
        if not id_pool:
            await asyncio.sleep(0.001)
            continue
        pkt_id = id_pool.pop()
        try:
            pkt = pyrad.packet.AuthPacket(secret=secret, id=pkt_id, dict=dictionary)
            if args.mac:
                ident = args.mac.replace(":", "").replace("-", "").lower()
                pkt["User-Name"] = ident
                pkt["User-Password"] = pkt.PwCrypt(ident)
            else:
                pkt["User-Name"] = args.user
                pkt["User-Password"] = pkt.PwCrypt(args.password)
            pkt.add_message_authenticator()
            wire = pkt.RequestPacket()
        except Exception:
            # pyrad quirk: an encrypted password that happens to start with
            # b"0x" trips EncodeOctets' hex-string path. Skip and re-roll —
            # the random request authenticator changes the ciphertext.
            id_pool.append(pkt_id)
            continue

        fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        proto.pending[pkt_id] = fut
        started = time.perf_counter()
        assert proto.transport is not None
        proto.transport.sendto(wire)
        try:
            data = await asyncio.wait_for(fut, timeout=args.timeout)
        except TimeoutError:
            proto.pending.pop(pkt_id, None)
            stats["timeout"] += 1
            continue
        finally:
            id_pool.append(pkt_id)
        stats["latencies"].append(time.perf_counter() - started)
        code = data[0]
        if code == pyrad.packet.AccessAccept:
            stats["accept"] += 1
        elif code == pyrad.packet.AccessReject:
            stats["reject"] += 1
        else:
            stats["other"] += 1


async def run(args: argparse.Namespace) -> int:
    dictionary = pyrad.dictionary.Dictionary(
        _DICT_PATH if os.path.isfile(_DICT_PATH) else None
    )
    loop = asyncio.get_running_loop()

    # RADIUS ids are one byte; one socket carries ≤256 outstanding requests.
    # Spread workers over as many sockets as needed.
    n_sockets = max(1, (args.concurrency + 199) // 200)
    protos: list[_Client] = []
    for _ in range(n_sockets):
        _t, proto = await loop.create_datagram_endpoint(
            _Client, remote_addr=(args.host, args.port),
        )
        protos.append(proto)

    stats: dict = {"accept": 0, "reject": 0, "other": 0, "timeout": 0, "latencies": []}
    stop_at = time.monotonic() + args.duration

    id_pools = [list(range(256)) for _ in protos]
    workers = [
        asyncio.create_task(_worker(
            protos[i % n_sockets], args, dictionary, stop_at, stats,
            id_pools[i % n_sockets],
        ))
        for i in range(args.concurrency)
    ]
    t0 = time.monotonic()
    await asyncio.gather(*workers)
    elapsed = time.monotonic() - t0

    for proto in protos:
        assert proto.transport is not None
        proto.transport.close()

    lat = stats["latencies"]
    done = len(lat)
    print(f"target        : {args.host}:{args.port}")
    print(f"mode          : {'MAB ' + args.mac if args.mac else 'PAP ' + args.user}")
    print(f"concurrency   : {args.concurrency} over {n_sockets} socket(s)")
    print(f"duration      : {elapsed:.1f}s")
    print(f"completed     : {done}  (accept={stats['accept']} reject={stats['reject']} "
          f"other={stats['other']} timeout={stats['timeout']})")
    if done:
        lat.sort()
        print(f"throughput    : {done / elapsed:,.0f} auth/s")
        print(f"latency p50   : {statistics.median(lat) * 1000:.1f} ms")
        print(f"latency p95   : {lat[int(done * 0.95) - 1] * 1000:.1f} ms")
        print(f"latency p99   : {lat[int(done * 0.99) - 1] * 1000:.1f} ms")
    if stats["timeout"] and stats["timeout"] > done:
        print("WARNING: more timeouts than completions — server saturated or unreachable",
              file=sys.stderr)
        return 1
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1812)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--mac", help="MAB benchmark: MAC used as user-name AND password")
    ap.add_argument("--user", help="PAP benchmark username")
    ap.add_argument("--password", help="PAP benchmark password")
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()
    if not args.mac and not (args.user and args.password):
        ap.error("either --mac or --user/--password is required")
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
