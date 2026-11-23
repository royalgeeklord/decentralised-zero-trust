"""E2: gateway authorisation latency and throughput.

Latency: N enrolled devices x M ledger records x lookup mode (cache/indexed/scan),
R sequential sessions each, over loopback TCP. Reports gateway processing time
(what a battery device's radio waits for, minus network RTT) and end-to-end time.
Throughput: concurrent client processes against one gateway.
"""
import asyncio, json, multiprocessing as mp, os, random, statistics as st, sys, tempfile, time
from dzthome.ledger import Ledger
from dzthome.gateway import Gateway
from dzthome.devices import Device, GOOD_FW

R = int(os.environ.get("E2_R", 300))


def pct(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p / 100
    f = int(k); c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


async def latency_config(n_dev, n_rec, mode):
    tmp = tempfile.mkdtemp()
    L = Ledger(f"{tmp}/l.db", f"{tmp}/w.db", lookup_mode=mode)
    gw = Gateway(L, nas_dir=tmp)
    port = await gw.start()
    devs = []
    for i in range(n_dev):
        d = Device("camera", "127.0.0.1", port); gw.enrol(d, "camera", GOOD_FW["camera"]); devs.append(d)
    L.bulk_fill(n_rec, [d.device_id for d in devs])
    e2e = []
    rnd = random.Random(1)
    for _ in range(R):
        d = rnd.choice(devs)
        t = time.perf_counter(); r, _ = await d.session("recorder", "video"); e2e.append(time.perf_counter() - t)
        assert r["ok"], r
    gw.server.close()
    g = [x[2] for x in gw.timing]; v = [x[0] for x in gw.timing]; l = [x[1] for x in gw.timing]
    ms = lambda xs, p: round(1000 * pct(xs, p), 3)
    return dict(devices=n_dev, records=n_rec, mode=mode,
                gw_p50=ms(g, 50), gw_p95=ms(g, 95), gw_p99=ms(g, 99),
                verify_p50=ms(v, 50), ledger_p50=ms(l, 50),
                e2e_p50=ms(e2e, 50), e2e_p95=ms(e2e, 95))


# ------------------------------------------------------------- throughput
def client_proc(port, uds, n, q):
    d = Device("camera", "127.0.0.1", port, uds=uds); d.boot(GOOD_FW["camera"])
    async def run():
        lat = []
        for _ in range(n):
            t = time.perf_counter(); r, _ = await d.session("recorder", "video"); lat.append(time.perf_counter() - t)
        return lat
    q.put(asyncio.run(run()))


def gateway_proc(n_dev, n_rec, ready, stop, devq):
    import pickle
    async def run():
        tmp = tempfile.mkdtemp()
        L = Ledger(f"{tmp}/l.db", f"{tmp}/w.db")
        gw = Gateway(L, nas_dir=tmp); port = await gw.start()
        devs = []
        for i in range(n_dev):
            d = Device("camera", "127.0.0.1", port); gw.enrol(d, "camera", GOOD_FW["camera"]); devs.append(d)
        L.bulk_fill(n_rec, [d.device_id for d in devs])
        for d in devs:
            devq.put((d._uds, port))
        ready.set()
        while not stop.is_set():
            await asyncio.sleep(0.05)
        gw.server.close()
    asyncio.run(run())


def throughput(conc, total=600, n_dev=100, n_rec=10_000):
    ready, stop, devq, q = mp.Event(), mp.Event(), mp.Queue(), mp.Queue()
    g = mp.Process(target=gateway_proc, args=(n_dev, n_rec, ready, stop, devq)); g.start()
    devs = [devq.get() for _ in range(n_dev)]
    ready.wait()
    port = devs[0][1]
    per = total // conc
    t0 = time.perf_counter()
    ps = [mp.Process(target=client_proc, args=(port, devs[i % n_dev][0], per, q)) for i in range(conc)]
    [p.start() for p in ps]
    lat = []
    for _ in ps:
        lat += q.get()
    el = time.perf_counter() - t0
    [p.join() for p in ps]; stop.set(); g.join()
    return dict(concurrency=conc, sessions=len(lat), sessions_per_s=round(len(lat) / el, 1),
                p50_ms=round(1000 * pct(lat, 50), 2), p95_ms=round(1000 * pct(lat, 95), 2))


if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    rows = []
    for mode in ("cache", "indexed", "scan"):
        for n_dev in (10, 100, 1000):
            for n_rec in (1_000, 10_000, 100_000):
                r = asyncio.run(latency_config(n_dev, n_rec, mode)); rows.append(r); print(r, flush=True)
    json.dump(rows, open("results/e2_latency.json", "w"), indent=1)
    tp = []
    for c in (1, 4, 16, 32):
        r = throughput(c); tp.append(r); print(r, flush=True)
    json.dump(tp, open("results/e2_throughput.json", "w"), indent=1)
