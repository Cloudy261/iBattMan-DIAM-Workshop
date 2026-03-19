"""
iBattMan DIAM Workshop – Use Case 1
════════════════════════════════════════════════════════════════
Battery Pass Ingestion via Verifiable Credentials (VCs)

Flow mirrors Section 4.5 / Figure 5 of iBattMan D5.4.
"""

import json, time, hashlib, copy

from did_helper import (
    DIDManager, b58encode, b58decode,
    banner, step, info, ok, warn, err, pause,
    BOLD, CYAN, GREEN, YELLOW, RED, DIM, RESET, MAGENTA, WHITE, BLUE,
)

# ── Actors ───────────────────────────────────────────────────────────────────
bms                  = DIDManager("BMS_Unit_001")
battery_pass_backend = DIDManager("Battery_Pass_Backend")   # truly independent


# ═══════════════════════════════════════════════════════════════════════════════
# BMS side – issue & sign a VC
# ═══════════════════════════════════════════════════════════════════════════════
def generate_battery_vc() -> dict:
    step(1, "BMS collects real-time health metrics", WHITE)
    health_data = {
        "soh":             94.5,
        "cycles":          450,
        "temperature_avg": 35.2,
        "timestamp":       time.time(),
    }
    info("State of Health",   f"{health_data['soh']} %")
    info("Charge Cycles",     str(health_data["cycles"]))
    info("Avg. Temperature",  f"{health_data['temperature_avg']} °C")
    info("Timestamp",         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    step(2, "BMS constructs the Verifiable Credential payload", WHITE)
    credential = {
        "@context":    ["https://www.w3.org/2018/credentials/v1"],
        "id":           "urn:uuid:ibattman-vc-001",
        "type":        ["VerifiableCredential", "BatteryHealthCredential"],
        "issuer":       bms.get_did(),
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "credentialSubject": {
            "id":            "urn:uuid:battery-serial-12345",
            "healthMetrics": health_data,
            "role":          "OEM_Data_Provider",
        },
    }
    info("Issuer DID",   bms.short_did(), CYAN)
    info("Subject",      credential["credentialSubject"]["id"], DIM)
    info("Role encoded", "OEM_Data_Provider", YELLOW)

    step(3, "BMS signs VC with Ed25519 private key (HSM in production)", WHITE)
    payload_bytes = json.dumps(credential, sort_keys=True).encode()
    signature     = bms.sign_message(payload_bytes)
    credential["proof"] = {
        "type":               "Ed25519Signature2020",
        "verificationMethod": f"{bms.get_did()}#key-1",
        "signatureValue":     b58encode(signature).decode(),
    }
    info("Signature (b58)", b58encode(signature).decode()[:32] + "…", DIM)
    ok("VC created and signed — ready to transmit to Battery-Pass Backend")
    return credential


# ═══════════════════════════════════════════════════════════════════════════════
# Battery-Pass Backend – receive, verify, store
# ═══════════════════════════════════════════════════════════════════════════════
def receive_and_store(vc_data: dict, label: str = "original") -> bool:
    step(4, f"Battery-Pass Backend receives VC  [{label}]", WHITE)
    vc_copy    = copy.deepcopy(vc_data)
    proof      = vc_copy.pop("proof")
    signature  = b58decode(proof["signatureValue"])
    issuer_did = vc_copy["issuer"]

    info("Claimed issuer DID",   issuer_did[:24] + "…", CYAN)
    info("Verification method",  proof["verificationMethod"][:32] + "…", DIM)

    step(5, "Backend resolves DID → rebuilds public key → verifies signature", WHITE)
    print(f"  {DIM}  (No central authority needed — key is embedded in the DID){RESET}")

    payload_bytes = json.dumps(vc_copy, sort_keys=True).encode()
    # Static call — battery_pass_backend has NO access to bms private key
    is_valid = DIDManager.verify_signature(payload_bytes, signature, issuer_did)

    if not is_valid:
        err("Signature verification FAILED — VC rejected")
        info("Reason", "Payload was modified after signing", RED)
        return False

    ok("Cryptographic signature verified ✔")

    step(6, "Role-Based Access Check", WHITE)
    role = vc_copy["credentialSubject"]["role"]
    info("Encoded role", role, GREEN if role == "OEM_Data_Provider" else RED)
    if role != "OEM_Data_Provider":
        warn(f"Role '{role}' not authorised for Battery-Pass write access")
        return False
    ok("Role authorised — data accepted for Battery-Pass storage")

    step(7, "Mock ledger commit (tamper-evident audit trail)", WHITE)
    tx_id = hashlib.sha256(payload_bytes).hexdigest()
    info("Transaction ID", tx_id[:32] + "…", DIM)
    info("Action",         "STORE", GREEN)
    info("Verified",       "True",  GREEN)
    ok("Ledger entry committed — full traceability established")
    return True


# ── Attacker ─────────────────────────────────────────────────────────────────
def tamper_vc(vc_data: dict) -> dict:
    t = copy.deepcopy(vc_data)
    t["credentialSubject"]["healthMetrics"]["soh"] = 99.9
    t["credentialSubject"]["role"] = "Admin"
    return t


# ═══════════════════════════════════════════════════════════════════════════════
def run():
    banner("iBattMan DIAM Workshop", CYAN)
    banner("Use Case 1 – Battery Pass Ingestion via Verifiable Credentials", BLUE)
    print(f"""
  {WHITE}Scenario:{RESET}
  The BMS periodically wraps health metrics in a {CYAN}Verifiable Credential{RESET}
  (W3C VC spec), signed with its Ed25519 key.  The Battery-Pass Backend
  verifies {BOLD}without{RESET} contacting any central authority — the public key
  is {CYAN}embedded in the DID string{RESET}.

  {YELLOW}Two runs:{RESET}
    A) Happy path  — legitimate VC reaches the backend
    B) Attack path — attacker tampers with the payload mid-transit
    """)

    pause("Start Happy Path →")

    # A: Happy path
    banner("A  —  Happy Path", GREEN)
    vc = generate_battery_vc()
    pause("VC signed by BMS — transmitting to Battery-Pass Backend →")
    result = receive_and_store(vc, label="legitimate")
    print(f"\n  {GREEN}{BOLD}{'─'*60}")
    print(f"  OUTCOME: {'Battery-Pass updated successfully. ✔' if result else 'Unexpected failure.'}")
    print(f"  {'─'*60}{RESET}")

    pause("Now simulate an attacker tampering with the VC in transit →")

    # B: Tamper path
    banner("B  —  Attack Path  (Tampering)", RED)
    print(f"""
  {RED}Attacker intercepts the VC and modifies:{RESET}
    • SoH:  {YELLOW}94.5 %  →  99.9 %{RESET}   (inflate battery health for resale fraud)
    • Role: {YELLOW}OEM_Data_Provider  →  Admin{RESET}  (privilege escalation attempt)
    """)
    vc_fresh    = generate_battery_vc()
    vc_tampered = tamper_vc(vc_fresh)
    pause("Tampered VC in transit — Backend receives it →")
    step(4, "Battery-Pass Backend receives VC  [tampered]", WHITE)
    info("Modified SoH",  "99.9 %  (was 94.5 %)", RED)
    info("Modified Role", "Admin   (was OEM_Data_Provider)", RED)
    receive_and_store(vc_tampered, label="tampered")
    print(f"\n  {RED}{BOLD}{'─'*60}")
    print(f"  OUTCOME: Tampered VC rejected. Fraud attempt neutralised. ✘")
    print(f"  {'─'*60}{RESET}")

    banner("Use Case 1 Complete", CYAN)
    print(f"""
  {WHITE}Key takeaways:{RESET}
  {GREEN}•{RESET} Each BMS has a unique cryptographic identity (DID).
  {GREEN}•{RESET} Credentials are self-contained — no central auth server needed.
  {GREEN}•{RESET} Any modification after signing is {RED}immediately detected{RESET}.
  {GREEN}•{RESET} Role-based access control is {CYAN}encoded inside the credential{RESET}.
  {GREEN}•{RESET} Every accepted VC produces an immutable ledger entry.
    """)

if __name__ == "__main__":
    run()