"""Emulated smart-home devices and attacker actions."""
import asyncio, json, os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .dice import DiceDevice

GOOD_FW = {
    "camera":  b"camera-firmware v2.4.1 " + b"\x00" * 4096,
    "sensor":  b"sensor-firmware v1.0.3 " + b"\x00" * 2048,
    "heating": b"heating-controller v3.2.0 " + b"\x00" * 4096,
}


class Device(DiceDevice):
    def __init__(self, kind, host, port, uds=None):
        super().__init__(uds)
        self.kind, self.host, self.port = kind, host, port
        self.locked = False                         # ransomware lock (heating controller)
        self.setpoint = 20.0

    def flash(self, image: bytes):
        """Authenticated firmware update followed by measured reboot."""
        self.boot(image)
        self.locked = image.startswith(b"RANSOM")

    async def _rpc(self, msgs):
        r, w = await asyncio.open_connection(self.host, self.port, limit=2**23)
        out = []
        try:
            for m in msgs:
                if callable(m):
                    m = m(out[-1])
                    if m is None:
                        break
                w.write((json.dumps(m) + "\n").encode()); await w.drain()
                out.append(json.loads(await r.readline()))
        finally:
            w.close()
        return out

    async def session(self, dst, svc, replay_evidence=None):
        """Algorithm 1 from the device side. Returns (response, evidence)."""
        req = f"{self.device_id}|{dst}|{svc}".encode()
        holder = {}

        def attest(prev):
            if not prev.get("ok"):
                return None
            ev = replay_evidence or self.attest(bytes.fromhex(prev["nonce"]), req)
            holder["ev"] = ev
            return {"type": "attest", "evidence": ev}
        out = await self._rpc([{"type": "hello", "devid": self.device_id, "dst": dst, "svc": svc}, attest])
        return out[-1], holder.get("ev")

    async def access(self, tok, dst, svc, op, **args):
        m = {"type": "access", "devid": self.device_id, "dst": dst, "svc": svc,
             "token": tok.get("token", ""), "exp": tok.get("exp", 0), "op": op, "args": args}
        return (await self._rpc([m]))[0]

    def command(self, setpoint):
        """Energy-service command from the hub (served only if not locked)."""
        if self.locked:
            return {"ok": False, "reason": "LOCKED: pay 0.5 BTC"}
        self.setpoint = setpoint
        return {"ok": True}


def encrypt_file(path, key):
    """Benign stand-in for a ransomware encryptor (synthetic files only)."""
    data = open(path, "rb").read()
    ct = ChaCha20Poly1305(key).encrypt(os.urandom(12), data, None)
    open(path + ".akira", "wb").write(ct)
    os.remove(path)
