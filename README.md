# iBattMan DIAM Workshop

Proof-of-concept implementation of **Decentralised Identity & Access Management (DIAM)** for Battery Management Systems, developed as part of the [iBattMan](https://www.ibattman.eu) Horizon Europe project (Grant No. 101138856).

Demonstrates three use cases from deliverable **D5.4 §4.5** using W3C DIDs, Verifiable Credentials, and Ed25519 cryptography — with interactive attack simulations for each.

---

## Prerequisites

```
Python 3.10+
pip install cryptography
```

That's it. Base58 and CBOR are implemented as stdlib-only shims inside `did_helper.py` — no extra packages needed.

---

## Files

| File | Description |
|---|---|
| `did_helper.py` | Shared foundation: `DIDManager`, Ed25519 signing/verification, base58, CBOR, ANSI terminal helpers |
| `use-case-1.py` | UC1 — Battery Pass ingestion via W3C Verifiable Credentials |
| `use-case-2.py` | UC2 — ECU real-time data integrity over CAN bus (CBOR/CWT packets) |
| `use-case-3.py` | UC3 — OTA firmware authorisation via VC + UDS (Uptane-inspired) |


---

## Usage

Each script runs interactively with `Press Enter to continue` pauses — designed for live presentation.

```bash
python use-case-1.py   # Battery Pass: happy path + tamper attack
python use-case-2.py   # ECU telemetry: normal + over-temp + CAN spoofing
python use-case-3.py   # OTA update: authorised + downgrade replay + rogue flasher
```

Open `ibattman-diam-workshop.html` directly in any browser for the Teams-friendly version.

---

## What It Demonstrates

**UC1 — Battery Pass Ingestion**
The BMS wraps health metrics (SoH, cycles, temperature) in a signed W3C VC. The Battery-Pass backend verifies the Ed25519 signature by reconstructing the public key from the DID string alone — no central authority needed. An attack scenario shows that modifying even one byte (inflating SoH from 94.5% to 99.9%) is detected immediately.

**UC2 — ECU Real-Time Data Check**
The BMS broadcasts compact CBOR-encoded telemetry packets over CAN bus, each prefixed with a 64-byte Ed25519 signature. The VCU verifies before trusting any value and applies a local safety policy (temperature/voltage thresholds) only on authenticated data. A spoofing attack — claiming the BMS DID but signing with a different key — is rejected instantly.

**UC3 — OTA Firmware Authorisation**
Before opening any UDS programming session, the BMC checks three gates: a monotonic counter (prevents downgrade/replay), an Ed25519 signature (verifies the OEM Director DID), and an RBAC role claim (`OEM_Update_Agent`). The full UDS sequence (0x10 → 0x27 → 0x2E → 0x31 → 0x10 → 0x19) only executes after all three pass. Two attack scenarios are shown: a downgrade attempt with a stale counter, and a rogue workshop tool with no VC at all.

---

## Architecture Notes

All three use cases use `did:key` — the public key is mathematically embedded in the DID string itself, so verification requires zero network calls. This is appropriate for the PoC; a production deployment would add factory provisioning of trusted DIDs and a Verifiable Data Registry for revocation.

The implementation is a deliberate simplification of the [W3C DID Core v1.0](https://www.w3.org/TR/did-1.0/) and [VC Data Model v1.1](https://www.w3.org/TR/vc-data-model/) specifications. Known deviations from production-grade implementations are documented in `D5.4 §4.5` and the sanity-check notes in the workshop materials.

---

## Requirements Addressed

`CNT 015_001I` through `CNT 015_005I` — simulation of DIAM outside the real BMS architecture, covering key generation (Ed25519), W3C DID/VC specifications, and the two required use cases (Battery Pass + ECU data exchange). UC3 additionally addresses `CNT 006_005H`, `CNT 006_006H`, `CNT 006_012H`, and `CNT 009`.

---

## Funding

This work was carried out within the iBattMan project, funded by the European Union's Horizon Europe programme under grant agreement No 101138856. Views expressed are those of the authors only.