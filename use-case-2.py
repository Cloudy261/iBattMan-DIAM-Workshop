"""
iBattMan DIAM Workshop – Use Case 2
════════════════════════════════════════════════════════════════
ECU Real-Time BMS Data Check via Compact Verifiable Tokens (CWT)

Flow mirrors Section 4.5 of iBattMan D5.4.
CBOR encoding mirrors CWT (COSE/RFC 8392) for bandwidth efficiency.
"""

import time
from did_helper import (
    DIDManager, cbor_dumps, cbor_loads,
    banner, step, info, ok, warn, err, pause,
    BOLD, CYAN, GREEN, YELLOW, RED, DIM, RESET, MAGENTA, WHITE, BLUE,
)

# ── Actors ───────────────────────────────────────────────────────────────────
bms      = DIDManager("BMS_Unit_002")
vcu      = DIDManager("VCU_001")
attacker = DIDManager("Attacker_Node")   # has its OWN key pair

# ── Local safety policy (stored on VCU — no cloud query) ─────────────────────
POLICY = {"temp_max_C": 80.0, "voltage_min_V": 340.0, "voltage_max_V": 420.0}


# ═══════════════════════════════════════════════════════════════════════════════
# BMS side
# ═══════════════════════════════════════════════════════════════════════════════
def build_can_packet(temp_c: float, voltage_v: float, error_code: int = 0) -> bytes:
    step(1, "BMS reads sensors and assembles telemetry", WHITE)
    data = {"t": temp_c, "v": voltage_v, "err": error_code}
    info("Temperature", f"{temp_c} °C")
    info("Voltage",     f"{voltage_v} V")
    info("Error Code",  str(error_code))

    step(2, "BMS creates compact CBOR payload (CWT-style integer keys)", WHITE)
    cwt = {
        1: bms.get_did(),
        2: "urn:uuid:battery-serial-12345",
        3: data,
        4: int(time.time()),
    }
    payload_bytes = cbor_dumps(cwt)
    info("Payload size (CBOR)", f"{len(payload_bytes)} bytes  "
         f"{DIM}(vs ~{len(str(cwt))} bytes JSON){RESET}")
    info("Issuer DID", bms.short_did(), CYAN)

    step(3, "BMS signs payload (Ed25519 — 64-byte signature prefix)", WHITE)
    sig = bms.sign_message(payload_bytes)
    info("Signature", sig.hex()[:32] + "…", DIM)
    packet = sig + payload_bytes
    info("Total packet", f"{len(packet)} bytes")
    ok("CAN packet ready for broadcast")
    return packet


# ── Attacker ─────────────────────────────────────────────────────────────────
def build_spoofed_packet() -> bytes:
    """Claims BMS DID but signs with attacker's own key."""
    cwt = {
        1: bms.get_did(),   # ← stolen DID — wrong key will sign it
        2: "urn:uuid:battery-serial-12345",
        3: {"t": 38.0, "v": 395.0, "err": 0},
        4: int(time.time()),
    }
    payload_bytes = cbor_dumps(cwt)
    bad_sig = attacker.sign_message(payload_bytes)   # attacker's key ≠ BMS key
    return bad_sig + payload_bytes


# ═══════════════════════════════════════════════════════════════════════════════
# VCU side
# ═══════════════════════════════════════════════════════════════════════════════
def process_can_packet(packet: bytes, label: str = "packet") -> bool:
    step(4, f"VCU receives CAN packet  [{label}]", WHITE)
    info("Packet size", f"{len(packet)} bytes")

    sig           = packet[:64]
    payload_bytes = packet[64:]

    step(5, "VCU deserialises CBOR — extracts issuer DID", WHITE)
    try:
        decoded = cbor_loads(payload_bytes)
    except Exception as e:
        err(f"CBOR decode failed: {e}"); return False

    issuer_did = decoded[1]
    telemetry  = decoded[3]
    issued_at  = decoded.get(4, 0)
    info("Claimed issuer DID", issuer_did[:24] + "…", CYAN)
    info("Issued at", time.strftime("%H:%M:%S", time.localtime(issued_at)), DIM)

    step(6, "VCU verifies signature BEFORE trusting any value", WHITE)
    print(f"  {DIM}  (public key reconstructed from DID — zero network calls){RESET}")

    is_valid = DIDManager.verify_signature(payload_bytes, sig, issuer_did)
    if not is_valid:
        err("Signature FAILED — packet DISCARDED")
        info("Reason", "Signature does not match the DID's public key", RED)
        print(f"\n  {RED}Audit entry written. Gateway alerted.{RESET}")
        return False

    ok("Signature verified — data from trusted BMS ✔")

    step(7, "VCU applies local safety policy", WHITE)
    t, v, ec = telemetry["t"], telemetry["v"], telemetry["err"]
    t_ok = t  <= POLICY["temp_max_C"]
    v_ok = POLICY["voltage_min_V"] <= v <= POLICY["voltage_max_V"]
    info("Temperature", f"{t} °C",  GREEN if t_ok else RED)
    info("Voltage",     f"{v} V",   GREEN if v_ok else RED)
    info("Error Code",  str(ec),    GREEN if ec == 0 else RED)

    alerts = []
    if not t_ok: alerts.append(f"TEMP HIGH: {t} °C  >  limit {POLICY['temp_max_C']} °C")
    if not v_ok: alerts.append(f"VOLTAGE out of range: {v} V")
    if ec != 0:  alerts.append(f"ERROR CODE active: {ec}")

    if alerts:
        for a in alerts: warn(a)
        print(f"\n  {YELLOW}{BOLD}VCU triggers safety response (e.g. power de-rating / contactor open).{RESET}")
    else:
        ok("All telemetry within safe limits — no action required")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
def run():
    banner("iBattMan DIAM Workshop", CYAN)
    banner("Use Case 2 – ECU Real-Time BMS Data Check via CWT/CBOR", BLUE)
    print(f"""
  {WHITE}Scenario:{RESET}
  The BMS broadcasts compact {CYAN}CBOR-signed telemetry{RESET} over CAN bus.
  Each packet carries a 64-byte Ed25519 signature prefix.
  The VCU verifies {BOLD}before{RESET} acting — key from DID string only.
  {CYAN}No central server. No round-trip. Microsecond verification.{RESET}

  {YELLOW}Three runs:{RESET}
    A) Normal operation  — all values in safe range
    B) Safety alert      — over-temperature event detected
    C) Spoofed packet    — attacker injects forged telemetry
    """)

    pause("Start Normal Operation →")

    # A: Normal
    banner("A  —  Normal Operation", GREEN)
    pkt = build_can_packet(temp_c=35.2, voltage_v=398.5)
    pause("Packet built — VCU receives it →")
    process_can_packet(pkt, label="normal telemetry")
    print(f"\n  {GREEN}{BOLD}{'─'*60}")
    print(f"  OUTCOME: Telemetry accepted. No alerts. System nominal. ✔")
    print(f"  {'─'*60}{RESET}")

    pause("Simulate an over-temperature event →")

    # B: Over-temp
    banner("B  —  Safety Alert  (Over-Temperature)", YELLOW)
    print(f"""
  {YELLOW}Battery temperature spikes during fast charging.
  BMS broadcasts updated telemetry — VCU must respond.{RESET}
    """)
    pkt_hot = build_can_packet(temp_c=92.4, voltage_v=415.0, error_code=3)
    pause("Hot packet transmitted — VCU receives it →")
    process_can_packet(pkt_hot, label="over-temp telemetry")
    print(f"\n  {YELLOW}{BOLD}{'─'*60}")
    print(f"  OUTCOME: Verified data triggered safety policy. Power de-rated. ⚠")
    print(f"  {'─'*60}{RESET}")

    pause("Simulate an attacker injecting a spoofed packet →")

    # C: Spoofed
    banner("C  —  Attack Path  (Spoofed Packet)", RED)
    print(f"""
  {RED}Attacker on the CAN bus forges a packet:{RESET}
    • Claims the legitimate BMS DID  (copied from a previous broadcast)
    • Signs with {RED}their own private key{RESET} — cannot steal BMS key
    • Goal: inject false sensor data to suppress safety cut-off
    """)
    spoofed = build_spoofed_packet()
    pause("Spoofed packet injected — VCU receives it →")
    process_can_packet(spoofed, label="spoofed packet")
    print(f"\n  {RED}{BOLD}{'─'*60}")
    print(f"  OUTCOME: Spoofed packet detected and discarded. Attack failed. ✘")
    print(f"  {'─'*60}{RESET}")

    banner("Use Case 2 Complete", CYAN)
    print(f"""
  {WHITE}Key takeaways:{RESET}
  {GREEN}•{RESET} CBOR encoding keeps overhead minimal ({CYAN}< 100 bytes per packet{RESET}).
  {GREEN}•{RESET} Signature verified {CYAN}locally on VCU{RESET} — zero network latency.
  {GREEN}•{RESET} A stolen DID {RED}cannot{RESET} be abused without the matching private key.
  {GREEN}•{RESET} Safety policy acts {BOLD}only on authenticated data{RESET}.
  {GREEN}•{RESET} Rejected packets generate forensic audit entries automatically.
    """)

if __name__ == "__main__":
    run()