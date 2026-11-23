"""E1: security test cases against the running prototype (real TCP, real crypto)."""
import asyncio, json, os, sqlite3, tempfile, time, hashlib
from dzthome.ledger import Ledger, _h
from dzthome.gateway import Gateway
from dzthome.devices import Device, GOOD_FW
from dzthome.dice import DiceDevice

RESULTS = []


def record(tid, name, expected, observed, passed, detail=""):
    RESULTS.append(dict(id=tid, test=name, expected=expected, observed=observed, passed=passed, detail=detail))
    print(f"{tid:4} {'PASS' if passed else 'FAIL'}  {name}: {observed} {detail}")


async def main():
    tmp = tempfile.mkdtemp()
    L = Ledger(f"{tmp}/ledger.db", f"{tmp}/witness.db")
    gw = Gateway(L, nas_dir=tmp)
    port = await gw.start()
    cam = Device("camera", "127.0.0.1", port); gw.enrol(cam, "camera", GOOD_FW["camera"])
    pc = Device("pc", "127.0.0.1", port); gw.enrol(pc, "pc", b"pc-image")
    heat = Device("heating", "127.0.0.1", port); gw.enrol(heat, "heating", GOOD_FW["heating"])
    os.makedirs(f"{tmp}/share", exist_ok=True); gw.nas_dir = f"{tmp}/share"
    open(f"{tmp}/share/report.docx", "wb").write(os.urandom(1024))

    # T1 legitimate session
    r, ev = await cam.session("recorder", "video")
    record("T1", "Legitimate camera to recorder", "ALLOW", "ALLOW" if r["ok"] else r["reason"], r["ok"])
    r2, _ = await pc.session("nas", "smb")
    a = await pc.access(r2, "nas", "smb", "list")
    record("T2", "Legitimate PC to NAS share", "ALLOW", "ALLOW" if a["ok"] else a["reason"], a["ok"])

    # T3 compromised camera (run-time exploit) tries SMB: denied, alerted, quarantined after 3
    n0 = len(gw.alerts); verdicts = []
    for _ in range(3):
        r, _ = await cam.session("nas", "smb"); verdicts.append(r.get("reason", "ALLOW"))
    q = L.device_state(cam.device_id)["quarantined"]
    r, _ = await cam.session("recorder", "video")
    record("T3", "Compromised camera requests SMB", "DENY + alert; quarantine after 3",
           f"{verdicts}; alerts={len(gw.alerts)-n0}; quarantined={q}; later video={r.get('reason','ALLOW')}",
           verdicts == ["POLICY"] * 3 and q and not r["ok"])
    gw.reprovision(cam, hashlib.sha256(GOOD_FW["camera"]).hexdigest())  # restore for next tests

    # T4 firmware implant: FWID changes -> attestation fails -> quarantine
    cam.flash(GOOD_FW["camera"] + b"implant: persistence hook")
    r, _ = await cam.session("recorder", "video")
    q = L.device_state(cam.device_id)["quarantined"]
    record("T4", "Persistent firmware implant", "ATTEST_FAIL + quarantine", f"{r.get('reason')}; quarantined={q}",
           r.get("reason") == "ATTEST_FAIL" and q)
    gw.reprovision(cam, hashlib.sha256(GOOD_FW["camera"]).hexdigest())

    # T5 replay of captured attestation evidence against a fresh nonce
    r, ev = await cam.session("recorder", "video")
    r_rep, _ = await cam.session("recorder", "video", replay_evidence=ev)
    record("T5", "Replay of captured evidence", "reject (nonce mismatch)", r_rep.get("reason", "ALLOW"),
           r_rep.get("reason") == "ATTEST_FAIL")
    gw.reprovision(cam, hashlib.sha256(GOOD_FW["camera"]).hexdigest())

    # T6 cloned device: same firmware, different hardware secret, claims camera's ID
    clone = Device("camera", "127.0.0.1", port); clone.boot(GOOD_FW["camera"])
    clone_id = cam.device_id
    clone.__class__ = type("Clone", (Device,), {"device_id": property(lambda s: clone_id)})
    r, _ = await clone.session("recorder", "video")
    record("T6", "Cloned device (different hardware secret)", "reject", r.get("reason", "ALLOW"),
           r.get("reason") == "ATTEST_FAIL", "side effect: legitimate device quarantined")
    gw.reprovision(cam, hashlib.sha256(GOOD_FW["camera"]).hexdigest())

    # T7 forged / altered token
    r, _ = await cam.session("recorder", "video")
    bad = dict(r); bad["exp"] = r["exp"] + 1000
    a = await cam.access(bad, "recorder", "video", "noop")
    a2 = await cam.access(r, "nas", "smb", "list")       # valid token used for another service
    record("T7", "Forged or re-targeted token", "reject both", f"{a.get('reason')}, {a2.get('reason')}",
           a.get("reason") == "BAD_TOKEN" and a2.get("reason") == "BAD_TOKEN")
    gw.reprovision(cam, hashlib.sha256(GOOD_FW["camera"]).hexdigest())

    # T8 ledger tampering (edit a record in place)
    db = sqlite3.connect(f"{tmp}/ledger.db")
    seq = db.execute("SELECT seq FROM records WHERE type='DECISION' AND body LIKE '%DENY%' LIMIT 1").fetchone()[0]
    db.execute("UPDATE records SET body=replace(body,'DENY','ALLOW') WHERE seq=?", (seq,)); db.commit()
    a = L.audit()
    record("T8", "Edit a DENY record to ALLOW", "chain break detected", f"valid={a['chain_valid']} at seq {a['first_bad_seq']}",
           not a["chain_valid"])

    # T9 ledger rewrite with consistent re-hashing (attacker controls main store)
    rows = db.execute("SELECT * FROM records ORDER BY seq").fetchall(); prev = "0" * 64
    for seq, ts, typ, devid, body, p, h in rows:
        nh = _h(prev, seq, ts, typ, devid, body)
        db.execute("UPDATE records SET prev=?, hash=? WHERE seq=?", (prev, nh, seq)); prev = nh
    db.commit()
    a = L.audit()
    record("T9", "Rewrite history with re-computed hashes", "witness mismatch detected",
           f"valid={a['chain_valid']}, witness_match={a['witness_head_match']}",
           a["chain_valid"] and not a["witness_head_match"])

    # T10 heating controller ransomware lock -> detection -> re-provision -> service restored
    L2 = Ledger(f"{tmp}/l2.db", f"{tmp}/w2.db"); gw.L = L2
    gw.enrol(heat, "heating", GOOD_FW["heating"])
    heat.flash(b"RANSOM lock firmware " + GOOD_FW["heating"])
    locked = heat.command(21.0)
    r, _ = await heat.session("hub", "telemetry")            # next heartbeat
    gw.reprovision(heat, hashlib.sha256(GOOD_FW["heating"]).hexdigest())
    r2, _ = await heat.session("hub", "telemetry")
    restored = heat.command(21.0)
    record("T10", "Heating controller lock and recovery", "detect, re-provision, restore",
           f"lock={locked['reason']}; heartbeat={r.get('reason')}; after={('ALLOW' if r2['ok'] else r2['reason'])}; command={'ok' if restored['ok'] else 'fail'}",
           (not locked["ok"]) and r.get("reason") == "ATTEST_FAIL" and r2["ok"] and restored["ok"])

    gw.server.close()
    json.dump(RESULTS, open("results/e1_security.json", "w"), indent=1)
    print(f"{sum(r['passed'] for r in RESULTS)}/{len(RESULTS)} passed")


if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    asyncio.run(main())
