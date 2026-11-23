"""DZT-Home gateway: policy decision/enforcement point (Algorithm 1), NAS proxy,
alerting, quarantine and re-provisioning. JSON-lines over TCP (asyncio)."""
import asyncio, hashlib, hmac, json, os, time
from .dice import verify_attestation, fwid_of
from .ledger import Ledger

ROLES = {
    "camera":  {("recorder", "video"), ("vendor-cloud", "https")},
    "sensor":  {("hub", "telemetry")},
    "heating": {("hub", "telemetry"), ("hub", "control")},
    "pc":      {("nas", "smb")},
}


class Gateway:
    def __init__(self, ledger: Ledger, nas_dir=None, token_ttl=300.0, deny_threshold=3,
                 deny_window=60.0, log_allows=True, enforce=True):
        self.L = ledger
        self.nas_dir = nas_dir
        self.secret = os.urandom(32)
        self.ttl = token_ttl
        self.deny_threshold, self.deny_window = deny_threshold, deny_window
        self.log_allows = log_allows
        self.enforce = enforce          # False = "VLAN-like": drop silently, no logging/alerts
        self.firmware_store = {}        # fwid -> image (known-good firmware)
        self.denials = {}               # devid -> [timestamps]
        self.alerts = []                # (time, devid, kind)
        self.server = None
        self.timing = []                # per-request (verify_s, ledger_s, total_s)

    # ------------------------------------------------------------ enrolment
    def enrol(self, dev, role, firmware):
        fw = fwid_of(firmware)
        self.firmware_store[fw] = firmware
        dev.boot(firmware)
        from .dice import pub_bytes
        self.L.append("ENROL", dev.device_id, fwid=fw, role=role, pub=pub_bytes(dev.device_key).hex())

    # ------------------------------------------------------------ helpers
    def _token(self, devid, dst, svc, exp):
        msg = f"{devid}|{dst}|{svc}|{exp:.3f}".encode()
        return hmac.new(self.secret, msg, hashlib.sha256).hexdigest()

    def _alert(self, devid, kind, **ev):
        self.alerts.append((time.perf_counter(), devid, kind))
        if self.enforce:
            self.L.append("ALERT", devid, kind=kind, **ev)

    def _quarantine(self, devid, why):
        st = self.L.device_state(devid)
        if st and not st["quarantined"]:
            self.L.append("QUARANTINE", devid, reason=why)

    def _deny(self, devid, dst, svc, reason):
        if not self.enforce:                       # silent drop (segmentation baseline)
            return {"ok": False, "reason": "unreachable"}
        self.L.append("DECISION", devid, dst=dst, svc=svc, verdict="DENY", reason=reason)
        self._alert(devid, "DENY_" + reason, dst=dst, svc=svc)
        now = time.time()
        q = [t for t in self.denials.get(devid, []) if now - t < self.deny_window] + [now]
        self.denials[devid] = q
        if len(q) >= self.deny_threshold:
            self._quarantine(devid, "repeated_denials")
        return {"ok": False, "reason": reason}

    # ------------------------------------------------------------ protocol
    async def handle(self, reader, writer):
        nonce = None; req = None
        try:
            while line := await reader.readline():
                m = json.loads(line)
                t0 = time.perf_counter()
                if m["type"] == "hello":
                    req = (m["devid"], m["dst"], m["svc"])
                    st = self.L.device_state(m["devid"])
                    if st is None:
                        resp = {"ok": False, "reason": "unknown_device"}
                    elif st["quarantined"]:
                        resp = self._deny(m["devid"], m["dst"], m["svc"], "QUARANTINED")
                    else:
                        nonce = os.urandom(16)
                        resp = {"ok": True, "nonce": nonce.hex()}
                elif m["type"] == "attest" and nonce is not None:
                    resp = self._authorise(req, m["evidence"], nonce, t0)
                    nonce = None                         # single use
                elif m["type"] == "access":
                    resp = self._access(m)
                else:
                    resp = {"ok": False, "reason": "protocol"}
                writer.write((json.dumps(resp) + "\n").encode())
                await writer.drain()
        except (ConnectionResetError, json.JSONDecodeError):
            pass
        finally:
            writer.close()

    def _authorise(self, req, ev, nonce, t0):
        devid, dst, svc = req
        st = self.L.device_state(devid)
        t1 = time.perf_counter()
        request = f"{devid}|{dst}|{svc}".encode()
        ok = verify_attestation(bytes.fromhex(st["pub"]), ev, nonce, request)
        t2 = time.perf_counter()
        if not ok or ev.get("fwid") != st["fwid"]:
            if self.enforce:
                self.L.append("DECISION", devid, dst=dst, svc=svc, verdict="DENY", reason="ATTEST_FAIL")
                self._alert(devid, "ATTEST_FAIL", fwid=ev.get("fwid", ""))
                self._quarantine(devid, "attestation_failure")
            return {"ok": False, "reason": "ATTEST_FAIL"}
        if (dst, svc) not in ROLES[st["role"]]:
            return self._deny(devid, dst, svc, "POLICY")
        exp = time.time() + self.ttl
        tok = self._token(devid, dst, svc, exp)
        t3 = time.perf_counter()
        if self.log_allows:
            self.L.append("DECISION", devid, dst=dst, svc=svc, verdict="ALLOW")
        t4 = time.perf_counter()
        self.timing.append((t2 - t1, (t1 - t0) + (t4 - t3), t4 - t0))
        return {"ok": True, "token": tok, "exp": exp}

    def _access(self, m):
        devid, dst, svc = m["devid"], m["dst"], m["svc"]
        st = self.L.device_state(devid)
        good = (st is not None and not st["quarantined"] and m.get("exp", 0) > time.time()
                and hmac.compare_digest(self._token(devid, dst, svc, m.get("exp", 0)), m.get("token", "")))
        if not good:
            return self._deny(devid, dst, svc, "BAD_TOKEN")
        if dst == "nas":
            return self._nas(m)
        return {"ok": True}

    def _nas(self, m):
        """Minimal SMB stand-in: list / read / write / rename in the share."""
        op, a = m["op"], m.get("args", {})
        p = lambda n: os.path.join(self.nas_dir, os.path.basename(n))
        if op == "list":
            return {"ok": True, "files": sorted(os.listdir(self.nas_dir))}
        if op == "read":
            return {"ok": True, "data": open(p(a["name"]), "rb").read().hex()}
        if op == "write":
            open(p(a["name"]), "wb").write(bytes.fromhex(a["data"])); return {"ok": True}
        if op == "delete":
            os.remove(p(a["name"])); return {"ok": True}
        return {"ok": False, "reason": "op"}

    # ------------------------------------------------------------ recovery
    def reprovision(self, dev, good_fwid):
        """Push known-good firmware (hash on the ledger) and re-enrol under a new epoch."""
        image = self.firmware_store[good_fwid]
        st = self.L.device_state(dev.device_id)
        dev.flash(image)                              # authenticated update + reboot (emulated)
        self.L.append("REPROVISION", dev.device_id, fwid=good_fwid, epoch=st["epoch"] + 1)
        self.L.append("RELEASE", dev.device_id, reason="reprovisioned")

    async def start(self, host="127.0.0.1", port=0):
        self.server = await asyncio.start_server(self.handle, host, port, limit=2**23)
        return self.server.sockets[0].getsockname()[1]
