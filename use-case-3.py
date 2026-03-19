"""
iBattMan DIAM Workshop – Use Case 3
════════════════════════════════════════════════════════════════
OTA Firmware Authorization via Verifiable Credentials + UDS

Actors
  • OEM Director  — signs firmware image + issues Update-VC (HSM)
  • ECD           — downloads image+VC, drives UDS session to BMC
  • BMC           — verifies VC before opening any programming session
  • Rogue Flasher — tries to open a session without a valid VC

Flow mirrors iBattMan D5.4 §4.2 (Uptane-inspired, 13-step procedure).
UDS service codes: 0x10 DiagSessionControl · 0x27 SecurityAccess
                   0x2E WriteDataByIdentifier · 0x31 RoutineControl
                   0x19 ReadDTCInformation

Three runs
  A) Authorized update  — happy path, all 10 milestones
  B) Downgrade attack   — valid signature, stale counter → rejected
  C) Rogue flasher      — no VC at all → UDS session denied
"""

import json, time, hashlib, copy, struct

from did_helper import (
    DIDManager, b58encode, b58decode,
    banner, step, info, ok, warn, err, pause,
    BOLD, CYAN, GREEN, YELLOW, RED, DIM, RESET, MAGENTA, WHITE, BLUE,
)

# ── Actors ────────────────────────────────────────────────────────────────────
oem_director = DIDManager("OEM_Director")      # signs everything
ecd          = DIDManager("ECD_Unit_001")       # authorized update agent
bmc          = DIDManager("BMC_Unit_001")       # verifier + flash target
rogue        = DIDManager("Rogue_Workshop_Tool")# has its own DID but no OEM VC

# ── BMC internal state (persisted across runs in this session) ────────────────
BMC_STATE = {
    "firmware_version": "v2.1.0",
    "counter":          41,           # monotonic, never decreases
    "trusted_oem_did":  oem_director.get_did(),
}

# ── Simulated firmware image (tiny, but real hash) ────────────────────────────
FIRMWARE_PAYLOAD = b"iBattMan_BMC_FW_v2.4.1_" + bytes(range(256)) * 4
FIRMWARE_HASH    = hashlib.sha256(FIRMWARE_PAYLOAD).hexdigest()
FIRMWARE_VERSION = "v2.4.1"
NEW_COUNTER      = BMC_STATE["counter"] + 1      # must be > current


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers – UDS frame pretty-printing
# ═══════════════════════════════════════════════════════════════════════════════
def uds_req(service_id: int, description: str, sub: str = "") -> None:
    sid = f"0x{service_id:02X}"
    tag = f"{CYAN}{BOLD}UDS {sid}{RESET}"
    print(f"      {tag}  {WHITE}{description}{RESET}", end="")
    if sub:
        print(f"  {DIM}({sub}){RESET}", end="")
    print()

def uds_resp(positive: bool, service_id: int, detail: str = "") -> None:
    if positive:
        resp = f"0x{service_id + 0x40:02X} positiveResponse"
        print(f"      {GREEN}{BOLD}← {resp}{RESET}  {DIM}{detail}{RESET}")
    else:
        print(f"      {RED}{BOLD}← 0x7F negativeResponse{RESET}  {RED}{detail}{RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
# OEM Director side – create & sign the Update-VC
# ═══════════════════════════════════════════════════════════════════════════════
def issue_update_vc(target_ecd_did: str) -> dict:
    """
    OEM Director creates a BatteryFirmwareUpdateCredential.
    The VC encodes:
      - which ECD is authorised to perform this update
      - which BMC is the target
      - the exact firmware hash and version
      - a monotonically increasing counter (anti-replay / anti-downgrade)
      - a role claim consumed by the BMC's RBAC check
    """
    step(1, "OEM Director signs firmware image (stored in HSM)", WHITE)
    info("Image hash (SHA-256)",  FIRMWARE_HASH[:32] + "…", DIM)
    info("Firmware version",      FIRMWARE_VERSION,          GREEN)
    info("Counter (new)",         str(NEW_COUNTER),           CYAN)
    info("OEM DID",               oem_director.short_did(),   CYAN)

    step(2, "OEM Director Repository creates Update-VC payload", WHITE)
    credential = {
        "@context":  ["https://www.w3.org/2018/credentials/v1"],
        "id":         "urn:uuid:ibattman-ota-vc-001",
        "type":      ["VerifiableCredential", "BatteryFirmwareUpdateCredential"],
        "issuer":     oem_director.get_did(),
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "expirationDate": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() + 86400)      # valid for 24 h
        ),
        "credentialSubject": {
            "id":              target_ecd_did,     # ECD authorised to flash
            "targetBmc":       "urn:uuid:bmc-serial-001",
            "firmwareHash":    FIRMWARE_HASH,
            "firmwareVersion": FIRMWARE_VERSION,
            "counter":         NEW_COUNTER,        # anti-replay field
            "role":            "OEM_Update_Agent", # RBAC claim for BMC
        },
    }
    info("Authorised ECD",   ecd.short_did(),  CYAN)
    info("Target BMC",       "urn:uuid:bmc-serial-001", DIM)
    info("Role encoded",     "OEM_Update_Agent", YELLOW)
    info("Expiry",           credential["expirationDate"], DIM)

    step(3, "OEM Director signs VC (Ed25519, private key in HSM)", WHITE)
    payload_bytes = json.dumps(credential, sort_keys=True).encode()
    signature = oem_director.sign_message(payload_bytes)
    credential["proof"] = {
        "type":               "Ed25519Signature2020",
        "verificationMethod": f"{oem_director.get_did()}#key-1",
        "signatureValue":     b58encode(signature).decode(),
    }
    info("Signature (b58)", b58encode(signature).decode()[:32] + "…", DIM)
    ok("Update-VC issued and signed — ready for ECD download (TLS)")
    return credential


# ═══════════════════════════════════════════════════════════════════════════════
# ECD side – download, verify locally, drive UDS session
# ═══════════════════════════════════════════════════════════════════════════════
def ecd_download_and_prepare(vc: dict) -> tuple:
    """ECD downloads the VC and image over TLS, verifies before touching BMC."""
    step(4, "ECD downloads Update-VC + encrypted image (TLS 1.3)", WHITE)
    info("Transport",   "TLS 1.3 + X.509 client certificate", GREEN)
    info("Image size",  f"{len(FIRMWARE_PAYLOAD)} bytes (AES-256-GCM in production)", DIM)

    # ECD pre-verifies the VC before engaging BMC
    step(5, "ECD pre-verifies Update-VC (fail fast, before any UDS traffic)", WHITE)
    vc_copy   = copy.deepcopy(vc)
    proof     = vc_copy.pop("proof")
    signature = b58decode(proof["signatureValue"])
    payload_b = json.dumps(vc_copy, sort_keys=True).encode()
    valid = DIDManager.verify_signature(payload_b, signature, vc_copy["issuer"])
    if not valid:
        err("ECD pre-check FAILED — aborting before UDS session")
        return None, None
    info("OEM signature", "VALID ✓", GREEN)
    info("Role claim",    vc_copy["credentialSubject"]["role"], YELLOW)
    ok("ECD pre-check passed — proceeding to BMC")
    return vc, FIRMWARE_PAYLOAD


# ═══════════════════════════════════════════════════════════════════════════════
# BMC side – receive VC, run all checks, execute UDS flashing sequence
# ═══════════════════════════════════════════════════════════════════════════════
def bmc_process_update(vc: dict, image: bytes) -> bool:
    """
    BMC gate-checks:
      1. Counter check (anti-replay / anti-downgrade)
      2. VC signature verification (Ed25519, from DID)
      3. RBAC role check
    Then opens UDS programming session and flashes.
    """
    if vc is None:
        err("No VC received — nothing to do")
        return False

    vc_copy   = copy.deepcopy(vc)
    proof     = vc_copy.pop("proof")
    signature = b58decode(proof["signatureValue"])
    subject   = vc_copy["credentialSubject"]

    # ── Gate 1: Counter ──────────────────────────────────────────────────────
    step(6, "BMC Gate 1 — Counter check (anti-replay / anti-downgrade)", WHITE)
    vc_counter  = subject["counter"]
    bmc_counter = BMC_STATE["counter"]
    info("BMC current counter", str(bmc_counter), DIM)
    info("VC counter",          str(vc_counter),  CYAN)
    if vc_counter <= bmc_counter:
        err(f"Counter {vc_counter} ≤ BMC counter {bmc_counter} — REPLAY / DOWNGRADE detected")
        uds_resp(False, 0x10, "conditionsNotCorrect (0x22)")
        return False
    ok(f"Counter {vc_counter} > {bmc_counter} — no replay possible")

    # ── Gate 2: Signature ────────────────────────────────────────────────────
    step(7, "BMC Gate 2 — VC signature verification (Ed25519, from DID string)", WHITE)
    info("Claimed OEM DID", vc_copy["issuer"][:24] + "…", CYAN)
    info("Netzwerk-Call",   "keiner — Public Key aus DID extrahiert", GREEN)
    payload_b = json.dumps(vc_copy, sort_keys=True).encode()
    is_valid  = DIDManager.verify_signature(payload_b, signature, vc_copy["issuer"])
    if not is_valid:
        err("OEM signature INVALID — programming session denied")
        uds_resp(False, 0x10, "securityAccessDenied (0x33)")
        return False
    ok("OEM signature VALID ✓")

    # ── Gate 3: RBAC ─────────────────────────────────────────────────────────
    step(8, "BMC Gate 3 — Role-Based Access Control", WHITE)
    role = subject.get("role", "")
    info("Required role",  "OEM_Update_Agent", DIM)
    info("Presented role", role, GREEN if role == "OEM_Update_Agent" else RED)
    if role != "OEM_Update_Agent":
        err(f"Role '{role}' not authorised for firmware updates")
        uds_resp(False, 0x10, "conditionsNotCorrect (0x22)")
        return False
    ok("Role authorised — all gates passed")

    # ── UDS 0x10: Open programming session ───────────────────────────────────
    step(9, "UDS 0x10 DiagnosticSessionControl — open programming session", WHITE)
    uds_req(0x10,  "DiagnosticSessionControl", "sub=0x02 programmingSession")
    uds_resp(True, 0x10, "programming session active")

    # ── UDS 0x27: Security access (VC presented as seed response) ────────────
    step(10, "UDS 0x27 SecurityAccess — VC-based authentication", WHITE)
    uds_req(0x27,  "SecurityAccess", "sub=0x01 requestSeed")
    info("Seed response", "Update-VC (signed by OEM Director)", CYAN)
    uds_resp(True, 0x27, "security access granted")

    # ── UDS 0x2E: Write image chunks ─────────────────────────────────────────
    step(11, "UDS 0x2E WriteDataByIdentifier — flash image in chunks", WHITE)
    chunk_size  = 256
    chunks      = [image[i:i+chunk_size] for i in range(0, len(image), chunk_size)]
    total       = len(chunks)
    info("Total chunks",  f"{total} × {chunk_size} bytes", DIM)
    info("Flash bank",    "Bank A (Bank B preserved for rollback)", DIM)
    info("Decryption",    "AES-256-GCM on-board (simulated)", DIM)

    # Simulate chunked transfer with a minimal ASCII progress bar
    bar_width = 40
    for i, chunk in enumerate(chunks, 1):
        filled = int(bar_width * i / total)
        bar    = "█" * filled + "░" * (bar_width - filled)
        pct    = int(100 * i / total)
        print(f"\r      {DIM}[{bar}] {pct:3d}%{RESET}", end="", flush=True)
    print()   # newline after bar
    uds_resp(True, 0x2E, f"{total} chunks written to flash")
    ok(f"Image written — {len(image)} bytes to Flash Bank A")

    # ── UDS 0x31: Verify hash ─────────────────────────────────────────────────
    step(12, "UDS 0x31 RoutineControl — verify image hash on-board", WHITE)
    uds_req(0x31,  "RoutineControl", "sub=verifyImage")
    expected_hash  = subject["firmwareHash"]
    calculated_hash = hashlib.sha256(image).hexdigest()
    info("Expected hash  (VC)", expected_hash[:32]   + "…", DIM)
    info("Calculated hash (BMC)", calculated_hash[:32] + "…",
         GREEN if calculated_hash == expected_hash else RED)
    if calculated_hash != expected_hash:
        err("Hash mismatch — update ABORTED, rollback initiated")
        uds_resp(False, 0x31, "generalProgrammingFailure (0x72)")
        return False
    uds_resp(True, 0x31, "image integrity verified ✓")

    # ── UDS 0x10: Return to default session + reboot ──────────────────────────
    step(13, "UDS 0x10 defaultSession — activate image, safe reboot", WHITE)
    uds_req(0x10,  "DiagnosticSessionControl", "sub=0x01 defaultSession")
    uds_resp(True, 0x10, "BMC rebooting into new firmware")

    # Update BMC state
    BMC_STATE["firmware_version"] = subject["firmwareVersion"]
    BMC_STATE["counter"]          = vc_counter
    info("New firmware version", BMC_STATE["firmware_version"], GREEN)
    info("New counter",          str(BMC_STATE["counter"]),      GREEN)

    # ── UDS 0x19: Read DTC status ─────────────────────────────────────────────
    step(14, "UDS 0x19 ReadDTCInformation — confirm zero fault codes", WHITE)
    uds_req(0x19,  "ReadDTCInformation", "sub=reportAllSupportedDTCs")
    uds_resp(True, 0x19, "DTC list empty — update successful")

    # Audit log entry
    audit_hash = hashlib.sha256(
        (subject["firmwareVersion"] + str(vc_counter)).encode()
    ).hexdigest()
    info("Audit entry hash", audit_hash[:32] + "…", DIM)
    ok("Key rotation triggered (symmetric session keys renewed)")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Attack helpers
# ═══════════════════════════════════════════════════════════════════════════════
def issue_downgrade_vc() -> dict:
    """
    OEM-signed VC with a stale counter — simulates a captured old VC
    being replayed (or an attacker uploading an old image to the Director).
    The signature IS valid; only the counter check catches this.
    """
    STALE_COUNTER = BMC_STATE["counter"] - 5   # old, definitely ≤ current

    credential = {
        "@context":  ["https://www.w3.org/2018/credentials/v1"],
        "id":         "urn:uuid:ibattman-ota-stale-001",
        "type":      ["VerifiableCredential", "BatteryFirmwareUpdateCredential"],
        "issuer":     oem_director.get_did(),
        "issuanceDate": "2024-03-01T10:00:00Z",   # old date
        "credentialSubject": {
            "id":              ecd.get_did(),
            "targetBmc":       "urn:uuid:bmc-serial-001",
            "firmwareHash":    hashlib.sha256(b"old firmware v1.8.0").hexdigest(),
            "firmwareVersion": "v1.8.0",
            "counter":         STALE_COUNTER,      # ← stale!
            "role":            "OEM_Update_Agent",
        },
    }
    payload_bytes = json.dumps(credential, sort_keys=True).encode()
    signature = oem_director.sign_message(payload_bytes)   # genuinely valid sig
    credential["proof"] = {
        "type":               "Ed25519Signature2020",
        "verificationMethod": f"{oem_director.get_did()}#key-1",
        "signatureValue":     b58encode(signature).decode(),
    }
    return credential, STALE_COUNTER


def rogue_attempt_session() -> None:
    """
    Rogue device sends UDS 0x10 programmingSession without presenting any VC.
    BMC issues a challenge; rogue has no valid OEM credential → denied.
    """
    step(1, "Rogue device sends UDS 0x10 programmingSession", WHITE)
    info("Rogue DID", rogue.short_did(), YELLOW)
    uds_req(0x10, "DiagnosticSessionControl", "sub=0x02 programmingSession")

    step(2, "BMC issues Security Access challenge — VC required", WHITE)
    uds_req(0x27, "SecurityAccess", "sub=0x01 requestSeed")
    info("Challenge",  "BMC requests BatteryFirmwareUpdateCredential", CYAN)
    info("Response",   "Rogue device has no valid OEM VC", RED)

    step(3, "No valid VC presented — BMC denies session + sets DTC", WHITE)
    uds_resp(False, 0x27, "securityAccessDenied (0x33)")
    info("UDS NRC",  "0x7F 0x10 0x33 securityAccessDenied", RED)
    info("DTC set",  "U0100 — UnauthorisedFlashAttempt", RED)
    info("Audit",    "Entry written to ECD forensic log", DIM)
    err("Session denied — rogue flash attempt neutralised")


# ═══════════════════════════════════════════════════════════════════════════════
# Main demo
# ═══════════════════════════════════════════════════════════════════════════════
def run():
    banner("iBattMan DIAM Workshop", CYAN)
    banner("Use Case 3 – OTA Firmware Authorization via VC + UDS", BLUE)
    print(f"""
  {WHITE}Scenario:{RESET}
  Before the ECD may flash new firmware onto the BMC, it must present
  a {CYAN}BatteryFirmwareUpdateCredential{RESET} issued and signed by the OEM
  Director (HSM).  The BMC verifies {BOLD}three gates{RESET} locally:
    1. Counter   — no replay / no downgrade possible
    2. Signature — Ed25519, public key from DID string (no network)
    3. Role      — RBAC claim must equal OEM_Update_Agent
  Only after all three pass does the BMC open a UDS programming session.
  Mirrors D5.4 §4.2 (Uptane-inspired) + CNT 006_005H / 006H / 012H / CNT 009.

  {YELLOW}Three runs:{RESET}
    A) Authorized update  — full 14-step happy path with flash progress
    B) Downgrade attack   — valid OEM signature but stale counter
    C) Rogue flasher      — no VC at all, UDS session denied
    """)

    # ── A: Authorized update ─────────────────────────────────────────────────
    pause("Start Authorized Update →")
    banner("A  —  Authorized OTA Update", GREEN)
    print(f"""
  {WHITE}BMC current state:{RESET}
    firmware  {CYAN}{BMC_STATE['firmware_version']}{RESET}
    counter   {CYAN}{BMC_STATE['counter']}{RESET}
    trusted DID  {DIM}{oem_director.short_did()}{RESET}
    """)

    vc = issue_update_vc(ecd.get_did())
    pause("Update-VC issued — ECD downloading + verifying →")

    vc_checked, image = ecd_download_and_prepare(vc)
    pause("ECD pre-check passed — engaging BMC over UDS →")

    result = bmc_process_update(vc_checked, image)

    print(f"\n  {GREEN}{BOLD}{'─'*60}")
    if result:
        print(f"  OUTCOME: Firmware {BMC_STATE['firmware_version']} active. Counter={BMC_STATE['counter']}. ✔")
    else:
        print(f"  OUTCOME: Update failed.")
    print(f"  {'─'*60}{RESET}")

    # ── B: Downgrade attack ───────────────────────────────────────────────────
    pause("Simulate a Downgrade / Replay Attack →")
    banner("B  —  Downgrade / Replay Attack", RED)
    stale_vc, stale_ctr = issue_downgrade_vc()
    print(f"""
  {RED}Attacker presents a captured OEM-signed VC:{RESET}
    version    {YELLOW}v1.8.0  (vulnerable firmware){RESET}
    counter    {YELLOW}{stale_ctr}  (BMC is now at {BMC_STATE['counter']}){RESET}
    signature  {GREEN}Formally valid (genuine OEM key){RESET}
    {RED}Threat: downgrade to known-vulnerable version for exploitation{RESET}
    """)
    pause("Stale VC presented to BMC →")

    step(6, "BMC Gate 1 — Counter check", WHITE)
    info("BMC current counter", str(BMC_STATE["counter"]), DIM)
    info("VC counter",          str(stale_ctr),            RED)
    err(f"Counter {stale_ctr} ≤ BMC counter {BMC_STATE['counter']} — REPLAY / DOWNGRADE")
    uds_resp(False, 0x10, "conditionsNotCorrect (0x22) — session denied")

    print(f"\n  {RED}{BOLD}{'─'*60}")
    print(f"  OUTCOME: Downgrade rejected at counter gate — no UDS session opened. ✘")
    print(f"  {'─'*60}{RESET}")

    # ── C: Rogue flasher ─────────────────────────────────────────────────────
    pause("Simulate a Rogue Flash Attempt →")
    banner("C  —  Rogue Flasher (No VC)", RED)
    print(f"""
  {RED}Rogue workshop tool attempts a programming session:{RESET}
    DID: {YELLOW}{rogue.short_did()}{RESET}
    Has its own key pair — {RED}but no OEM BatteryFirmwareUpdateCredential{RESET}
    Goal: flash unsigned/modified firmware
    """)
    pause("Rogue device on the CAN bus — session attempt →")
    rogue_attempt_session()

    print(f"\n  {RED}{BOLD}{'─'*60}")
    print(f"  OUTCOME: Rogue session denied. DTC U0100 set. Forensic audit written. ✘")
    print(f"  {'─'*60}{RESET}")

    # ── Summary ───────────────────────────────────────────────────────────────
    banner("Use Case 3 Complete", CYAN)
    print(f"""
  {WHITE}Key takeaways:{RESET}
  {GREEN}•{RESET} BMC verifies {CYAN}three independent gates{RESET} before any UDS session.
  {GREEN}•{RESET} Counter makes replay and downgrade attacks {RED}cryptographically impossible{RESET}.
  {GREEN}•{RESET} Public key reconstructed from DID — {CYAN}zero network calls on the BMC{RESET}.
  {GREEN}•{RESET} UDS session only opens after all gates pass — {BOLD}no trust without proof{RESET}.
  {GREEN}•{RESET} Rogue devices get a DTC + forensic audit entry automatically.
  {GREEN}•{RESET} Satisfies CNT 006_005H, CNT 006_006H, CNT 006_012H, CNT 009.
    """)


if __name__ == "__main__":
    run()