"""E3: Akira-style pivot replay with a real (benign) encryptor on a synthetic share.
E4: heating-controller lock -> detection -> re-provisioning -> service restored (timing).
E5: ledger audit time vs ledger size.
"""
import asyncio, hashlib, json, os, shutil, statistics as st, tempfile, time
from dzthome.ledger import Ledger
from dzthome.gateway import Gateway, ROLES
from dzthome.devices import Device, GOOD_FW, encrypt_file

N_FILES, FILE_KB, REPS = 1000, 64, 5


def make_share(path):
    os.makedirs(path, exist_ok=True)
    for i in range(N_FILES):
        with open(f"{path}/doc_{i:04d}.dat", "wb") as f:
            f.write(os.urandom(FILE_KB * 1024))


def count_encrypted(path):
    return sum(1 for n in os.listdir(path) if n.endswith(".akira"))


async def pivot(config):
    """config: S0 flat | S1 VLAN (silent drop) | S3 DZT-Home | S3-policy-error."""
    tmp = tempfile.mkdtemp(); share = f"{tmp}/share"; make_share(share)
    L = Ledger(f"{tmp}/l.db", f"{tmp}/w.db")
    gw = Gateway(L, nas_dir=share, enforce=(config != "S1"))
    port = await gw.start()
    cam = Device("camera", "127.0.0.1", port)
    role = "camera"
    if config == "S3-policy-error":
        ROLES["camera_misconfigured"] = ROLES["camera"] | {("nas", "smb")}; role = "camera_misconfigured"
    gw.enrol(cam, role, GOOD_FW["camera"])
    key = os.urandom(32)
    t0 = time.perf_counter(); attempts = 0; first_alert = quarantine_t = None

    if config == "S0":                                   # flat network: shares mounted directly
        for n in sorted(os.listdir(share)):
            encrypt_file(f"{share}/{n}", key)
    else:                                                # every access goes through the gateway PEP
        files = None
        for _ in range(20):                              # attacker retries, as an operator would
            attempts += 1
            r, _ = await cam.session("nas", "smb")
            if gw.alerts and first_alert is None:
                first_alert = gw.alerts[0][0] - t0
            st_ = L.device_state(cam.device_id)
            if st_ and st_["quarantined"] and quarantine_t is None:
                quarantine_t = time.perf_counter() - t0
            if r.get("ok"):
                lst = await cam.access(r, "nas", "smb", "list"); files = lst["files"]
                for n in files:                          # encrypt through the share protocol
                    d = await cam.access(r, "nas", "smb", "read", name=n)
                    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
                    ct = ChaCha20Poly1305(key).encrypt(os.urandom(12), bytes.fromhex(d["data"]), None)
                    await cam.access(r, "nas", "smb", "write", name=n + ".akira", data=ct.hex())
                    await cam.access(r, "nas", "smb", "delete", name=n)
                break
    el = time.perf_counter() - t0
    enc = count_encrypted(share)
    gw.server.close()
    out = dict(config=config, files_encrypted=enc, share_encrypted_pct=round(100 * enc / N_FILES, 1),
               elapsed_s=round(el, 3), attempts=attempts,
               alerts=len(gw.alerts), ledger_records=L.seq,
               first_alert_ms=round(1000 * first_alert, 2) if first_alert is not None else None,
               quarantine_ms=round(1000 * quarantine_t, 2) if quarantine_t is not None else None)
    shutil.rmtree(tmp)
    return out


async def recovery_trials(n=100):
    tmp = tempfile.mkdtemp()
    L = Ledger(f"{tmp}/l.db", f"{tmp}/w.db"); gw = Gateway(L, nas_dir=tmp); port = await gw.start()
    heat = Device("heating", "127.0.0.1", port); gw.enrol(heat, "heating", GOOD_FW["heating"])
    good = hashlib.sha256(GOOD_FW["heating"]).hexdigest()
    det, rest = [], []
    for _ in range(n):
        heat.flash(b"RANSOM lock firmware " + GOOD_FW["heating"])
        assert not heat.command(21.0)["ok"]
        t0 = time.perf_counter()
        r, _ = await heat.session("hub", "telemetry")          # next heartbeat
        assert r.get("reason") == "ATTEST_FAIL"
        t1 = time.perf_counter()
        gw.reprovision(heat, good)
        r2, _ = await heat.session("hub", "telemetry")
        assert r2["ok"] and heat.command(21.0)["ok"]
        t2 = time.perf_counter()
        det.append(t1 - t0); rest.append(t2 - t0)
    gw.server.close()
    q = lambda xs, p: round(1000 * sorted(xs)[int(p / 100 * (len(xs) - 1))], 2)
    return dict(trials=n, detect_p50_ms=q(det, 50), detect_p95_ms=q(det, 95),
                restore_p50_ms=q(rest, 50), restore_p95_ms=q(rest, 95))


def audit_times():
    out = []
    for n in (1_000, 10_000, 100_000):
        tmp = tempfile.mkdtemp(); L = Ledger(f"{tmp}/l.db", f"{tmp}/w.db")
        L.bulk_fill(n, ["dev0"])
        t = time.perf_counter(); a = L.audit(); el = time.perf_counter() - t
        out.append(dict(records=n, audit_s=round(el, 3), valid=a["chain_valid"]))
        shutil.rmtree(tmp)
    return out


if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    res = {}
    for cfg in ("S0", "S1", "S3", "S3-policy-error"):
        runs = [asyncio.run(pivot(cfg)) for _ in range(REPS)]
        res[cfg] = runs
        print(cfg, runs[0], flush=True)
    rec = asyncio.run(recovery_trials()); print(rec)
    aud = audit_times(); print(aud)
    json.dump(dict(pivot=res, recovery=rec, audit=aud, n_files=N_FILES, file_kb=FILE_KB, reps=REPS),
              open("results/e3_replay.json", "w"), indent=1)
