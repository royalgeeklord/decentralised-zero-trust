"""Coin-free, permissioned, hash-chained ledger with a witness replica.

Each record: seq, ts, type, devid, body (JSON), prev_hash, hash
  hash = SHA-256(prev_hash || seq || ts || type || devid || body)
The gateway is the only writer; every record is replicated synchronously to a
witness store so that rewriting history requires compromising both.
"""
import hashlib, json, sqlite3, time

GENESIS = "0" * 64
SCHEMA = """CREATE TABLE IF NOT EXISTS records(
  seq INTEGER PRIMARY KEY, ts REAL, type TEXT, devid TEXT, body TEXT, prev TEXT, hash TEXT)"""


def _h(prev, seq, ts, typ, devid, body):
    return hashlib.sha256(f"{prev}|{seq}|{ts:.6f}|{typ}|{devid}|{body}".encode()).hexdigest()


class Store:
    def __init__(self, path, index=True):
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute(SCHEMA)
        if index:
            self.db.execute("CREATE INDEX IF NOT EXISTS ix_dev ON records(devid, type)")

    def head(self):
        r = self.db.execute("SELECT seq, hash FROM records ORDER BY seq DESC LIMIT 1").fetchone()
        return r if r else (0, GENESIS)

    def insert(self, row):
        self.db.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?)", row)


class Ledger:
    """lookup_mode: 'cache' (in-memory state, default), 'indexed' (SQL with index)
    or 'scan' (SQL without index: worst case)."""

    STATE_TYPES = ("ENROL", "FWUPDATE", "REPROVISION", "QUARANTINE", "RELEASE")

    def __init__(self, path, witness_path, lookup_mode="cache"):
        self.mode = lookup_mode
        self.main = Store(path, index=(lookup_mode != "scan"))
        self.witness = Store(witness_path, index=False)
        self.seq, self.prev = self.main.head()
        self.state = {}                      # devid -> dict(fwid, role, pub, epoch, quarantined)
        self._rebuild_state()

    # -------------------------------------------------------------- write
    def append(self, typ, devid="", **body):
        self.seq += 1
        ts = time.time()
        b = json.dumps(body, sort_keys=True, separators=(",", ":"))
        h = _h(self.prev, self.seq, ts, typ, devid, b)
        row = (self.seq, ts, typ, devid, b, self.prev, h)
        self.main.insert(row)
        self.witness.insert(row)
        self.prev = h
        if typ in self.STATE_TYPES:
            self._apply(typ, devid, body)
        return h

    def bulk_fill(self, n, devids):
        """Pre-populate n DECISION records (for scaling experiments)."""
        self.main.db.execute("BEGIN"); self.witness.db.execute("BEGIN")
        for i in range(n):
            self.append("DECISION", devids[i % len(devids)], dst="recorder", svc="video", verdict="ALLOW")
        self.main.db.execute("COMMIT"); self.witness.db.execute("COMMIT")

    # -------------------------------------------------------------- state
    def _apply(self, typ, devid, body):
        s = self.state.setdefault(devid, {"quarantined": False, "epoch": 0})
        if typ == "ENROL":
            s.update(fwid=body["fwid"], role=body["role"], pub=body["pub"], epoch=0, quarantined=False)
        elif typ in ("FWUPDATE", "REPROVISION"):
            s["fwid"] = body["fwid"]; s["epoch"] = body.get("epoch", s["epoch"])
        elif typ == "QUARANTINE":
            s["quarantined"] = True
        elif typ == "RELEASE":
            s["quarantined"] = False

    def _rebuild_state(self):
        for typ, devid, body in self.main.db.execute(
                "SELECT type, devid, body FROM records WHERE type IN (?,?,?,?,?) ORDER BY seq",
                self.STATE_TYPES):
            self._apply(typ, devid, json.loads(body))

    def device_state(self, devid):
        if self.mode == "cache":
            return self.state.get(devid)
        # SQL path: reconstruct from the device's state records
        rows = self.main.db.execute(
            "SELECT type, body FROM records WHERE devid=? AND type IN (?,?,?,?,?) ORDER BY seq",
            (devid, *self.STATE_TYPES)).fetchall()
        if not rows:
            return None
        s = {"quarantined": False, "epoch": 0}
        for typ, body in rows:
            body = json.loads(body)
            if typ == "ENROL":
                s.update(fwid=body["fwid"], role=body["role"], pub=body["pub"], epoch=0, quarantined=False)
            elif typ in ("FWUPDATE", "REPROVISION"):
                s["fwid"] = body["fwid"]; s["epoch"] = body.get("epoch", s["epoch"])
            elif typ == "QUARANTINE":
                s["quarantined"] = True
            elif typ == "RELEASE":
                s["quarantined"] = False
        return s

    # -------------------------------------------------------------- audit
    @staticmethod
    def verify_chain(store):
        prev = GENESIS
        for seq, ts, typ, devid, body, p, h in store.db.execute("SELECT * FROM records ORDER BY seq"):
            if p != prev or _h(p, seq, ts, typ, devid, body) != h:
                return False, seq
            prev = h
        return True, None

    def audit(self):
        ok_main, bad = self.verify_chain(self.main)
        head_match = self.main.head() == self.witness.head()
        return {"chain_valid": ok_main, "first_bad_seq": bad, "witness_head_match": head_match}
