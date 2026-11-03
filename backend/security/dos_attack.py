"""
Denial-of-service attack against your OWN running server, for the before/after demo.

    python -m security.dos_attack --label defended
    python -m security.dos_attack --label undefended     # with DISABLED_DEFENCES=dos on the server

Phase 1, one expensive request: a single multi-megabyte URL is sent while a
"normal user" keeps checking an ordinary URL every 100 ms. We record how long
the normal user's requests take while the expensive one is in flight.

Phase 2, flood: many maximum-size requests at once. We count how many were
answered, rejected with 503, or failed, and how long /api/health took meanwhile.

Results are printed and saved to security/results/dos-<label>.json.
"""

import argparse
import asyncio
import json
import statistics
import time
from collections import Counter
from pathlib import Path

import httpx

RESULTS = Path(__file__).resolve().parent / 'results'
NORMAL_URL = 'https://www.example.com/account/settings'


def summarise(latencies_ms: list[float]) -> dict:
    if not latencies_ms:
        return {'count': 0}
    ordered = sorted(latencies_ms)
    return {
        'count': len(ordered),
        'median_ms': round(statistics.median(ordered), 1),
        'p95_ms': round(ordered[int(0.95 * (len(ordered) - 1))], 1),
        'max_ms': round(ordered[-1], 1),
    }


async def timed(coro) -> tuple[float, httpx.Response | Exception]:
    started = time.perf_counter()
    try:
        result = await coro
    except Exception as error:  # timeouts, refused connections
        result = error
    return (time.perf_counter() - started) * 1000, result


async def normal_user(client: httpx.AsyncClient, stop: asyncio.Event, latencies: list[float]) -> None:
    while not stop.is_set():
        elapsed, _ = await timed(client.post('/api/assess', json={'url': NORMAL_URL}))
        latencies.append(elapsed)
        await asyncio.sleep(0.1)


async def phase_expensive(base: str, megabytes: float) -> dict:
    huge_url = 'http://example.com/' + 'ab1/' * int(megabytes * 1024 * 1024 / 4)
    latencies: list[float] = []
    stop = asyncio.Event()
    async with httpx.AsyncClient(base_url=base, timeout=120) as attacker, \
            httpx.AsyncClient(base_url=base, timeout=120) as user:
        user_task = asyncio.create_task(normal_user(user, stop, latencies))
        await asyncio.sleep(0.5)  # baseline before the attack lands
        elapsed, response = await timed(attacker.post('/api/assess', json={'url': huge_url}))
        await asyncio.sleep(0.5)
        stop.set()
        await user_task
    status = response.status_code if isinstance(response, httpx.Response) else type(response).__name__
    return {
        'expensive_request': {'size_mb': megabytes, 'status': status, 'time_ms': round(elapsed, 1)},
        'normal_user_latency': summarise(latencies),
    }


async def phase_flood(base: str, concurrency: int) -> dict:
    big_url = 'http://example.com/' + 'x' * 2000
    health: list[float] = []
    limits = httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=concurrency + 10)
    # The probe is a separate client, like a different user, so it doesn't queue behind the attacker's connections.
    async with httpx.AsyncClient(base_url=base, timeout=60, limits=limits) as client, \
            httpx.AsyncClient(base_url=base, timeout=60) as other_user:
        async def probe():
            for _ in range(20):
                elapsed, _ = await timed(other_user.get('/api/health'))
                health.append(elapsed)
                await asyncio.sleep(0.05)

        started = time.perf_counter()
        results, _ = await asyncio.gather(
            asyncio.gather(*[timed(client.post('/api/assess', json={'url': big_url})) for _ in range(concurrency)]),
            probe(),
        )
        total = (time.perf_counter() - started) * 1000

    outcomes = Counter(r.status_code if isinstance(r, httpx.Response) else type(r).__name__ for _, r in results)
    return {
        'requests': concurrency,
        'outcomes': {str(k): v for k, v in outcomes.items()},
        'total_time_ms': round(total, 1),
        'request_latency': summarise([t for t, _ in results]),
        'health_latency_during_flood': summarise(health),
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base', default='http://127.0.0.1:8000')
    parser.add_argument('--label', required=True, help='e.g. defended / undefended')
    parser.add_argument('--megabytes', type=float, default=5)
    parser.add_argument('--concurrency', type=int, default=300)
    args = parser.parse_args()

    print(f'Phase 1: one {args.megabytes} MB request while a normal user keeps checking a URL...')
    expensive = await phase_expensive(args.base, args.megabytes)
    print(json.dumps(expensive, indent=2))

    print(f'Phase 2: {args.concurrency} maximum-size requests at once...')
    flood = await phase_flood(args.base, args.concurrency)
    print(json.dumps(flood, indent=2))

    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / f'dos-{args.label}.json'
    out.write_text(json.dumps({'label': args.label, 'expensive': expensive, 'flood': flood}, indent=2))
    print(f'Saved {out}')


if __name__ == '__main__':
    asyncio.run(main())
