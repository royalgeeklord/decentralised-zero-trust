# DZT-Home proof-of-concept prototype

Prototype of the decentralised zero-trust architecture for smart homes described in the paper, with the four experiments (E1–E4) reported in Sect. 5.

## Requirements
Python 3.10+, `pip install cryptography matplotlib` (SQLite is built into Python).
Runs unchanged on a Raspberry Pi 4 (Raspberry Pi OS 64-bit).

## Layout
| Path | Purpose |
|---|---|
| `dzthome/dice.py` | Emulated DICE: device secret, FWID, CDI, DeviceID and alias keys, alias certificate, attestation check |
| `dzthome/ledger.py` | Coin-free hash-chained ledger (SQLite, WAL) with synchronous witness replica, state cache, audit |
| `dzthome/gateway.py` | Policy engine (Algorithm 1), roles, tokens, alerts, quarantine, NAS proxy, re-provisioning |
| `dzthome/devices.py` | Emulated camera / sensor / heating controller / PC clients; benign encryptor |
| `exp1_security.py` | E1: ten security test cases (T1–T10) |
| `exp2_performance.py` | E2: authorisation latency (devices × ledger size × lookup mode) and throughput |
| `exp3_replay.py` | E3: Akira-style pivot replay on a synthetic 64 MB share; E4: lock/recovery timing and ledger audit |
| `fig_e2.py` | Figure 2 of the paper |
| `results/` | Outputs used in the paper (JSON) |

## Run
```bash
python3 exp1_security.py        # ~5 s
python3 exp2_performance.py     # ~1 min on a 2-core x86 VM; longer on a Pi
python3 exp3_replay.py          # ~1 min
python3 fig_e2.py
```

## Safety
The "encryptor" only encrypts synthetic random files it creates in a temporary directory. No real malware, no network access beyond loopback.

## Porting to the hardware testbed
Run `dzthome/gateway.py` on the Raspberry Pi (bind to the LAN address instead of 127.0.0.1) and implement the device side of
Algorithm 1 on ESP32 firmware (ESP-IDF: secure boot + mbedTLS ECDSA P-256), keeping the same JSON-lines messages.
