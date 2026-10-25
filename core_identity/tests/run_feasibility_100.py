#!/usr/bin/env python3
"""
Raw Feasibility Protocol Runner (100 Consecutive Trials).
Implements Section 6 Experimental Protocol & Chapter 4 Feasibility Evaluation for Xenoverify:
- Host profiling using high-resolution monotonic timer (time.perf_counter())
- Single-threaded cryptographic isolation
- 100 consecutive executions of complete Xenoverify pipeline:
    1. Key generation & Anchor in simulated DID Registry
    2. Salted attribute commitment & Merkle tree synthesis
    3. Post-Quantum Signing with final NIST FIPS 204 ML-DSA-65 (3,309-byte signature)
    4. Client-side selective disclosure proof extraction (2 revealed, 4 concealed)
    5. Verifier 5-stage pipeline: Nonce replay check, Revocation ledger,
       Independent DID registry key verification, Merkle proof tree climb,
       and NIST FIPS 204 ML-DSA-65 post-quantum signature verification.
- Output:
    - docs/feasibility_test_results.csv (raw CSV with 100 trials)
    - Comprehensive statistical analysis (Mean, Std Dev, p50, p95, Min, Max, 95% Confidence Intervals)
"""

import os
import sys
import time
import math
import csv
import json
import statistics
import tracemalloc
from datetime import datetime

# Setup Django Environment
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend_django.settings")

import django
django.setup()

from core_identity.models import DIDRegistry, IssuedCredential, VerifierNonce
from core_identity.crypto_service import PQCService
from core_identity.merkle_engine import SelectiveDisclosureEngine
from core_identity.services.issuer_service import IssuerService
from core_identity.services.credential_service import CredentialService
from core_identity.services.verification_service import VerificationService


def calculate_statistics(data):
    """Computes descriptive metrics and 95% Student-t confidence intervals."""
    n = len(data)
    mean_val = statistics.mean(data)
    std_val = statistics.stdev(data) if n > 1 else 0.0
    sorted_vals = sorted(data)
    p50_val = statistics.median(sorted_vals)
    p95_idx = int(math.ceil(0.95 * n)) - 1
    p95_val = sorted_vals[min(p95_idx, n - 1)]
    min_val = min(data)
    max_val = max(data)

    # Student's t critical value for 95% confidence with df = n-1 (t ~ 1.984 for n=100)
    # Using exact approximation for t-distribution at alpha=0.05
    t_critical = 1.984 if n >= 100 else 2.000
    ci_margin = t_critical * (std_val / math.sqrt(n)) if n > 1 else 0.0

    return {
        "n": n,
        "mean": round(mean_val, 3),
        "std": round(std_val, 3),
        "p50": round(p50_val, 3),
        "p95": round(p95_val, 3),
        "min": round(min_val, 3),
        "max": round(max_val, 3),
        "ci_95": round(ci_margin, 3),
        "ci_lower": round(max(0.0, mean_val - ci_margin), 3),
        "ci_upper": round(mean_val + ci_margin, 3),
    }


def run_feasibility_protocol(num_trials=100, output_csv=None):
    """
    Executes the 100-trial feasibility evaluation protocol.
    """
    if output_csv is None:
        output_csv = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "feasibility_test_results.csv"))

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    print("=" * 80)
    print("XENOVERIFY POST-QUANTUM FEASIBILITY PROTOCOL RUNNER")
    print("Standard: NIST FIPS 204 ML-DSA-65 (Module-Lattice Digital Signatures)")
    print(f"Trials: {num_trials} Consecutive Executions | Isolated Monotonic Clock (perf_counter)")
    print("=" * 80)

    # Synthetic applicant attributes
    attributes = {
        "fullName": "Alex Carter",
        "nin": "29837492812",
        "dob": "1992-06-14",
        "nationality": "Nigerian",
        "clearanceLevel": "Tier-3",
        "residence": "Victoria Island, Lagos"
    }
    disclosed_keys = ["fullName", "nationality"]

    # 1. Initialize dedicated test authority
    issuer, keypair = IssuerService.initialize_issuer(
        scheme="ML-DSA-65 (NIST FIPS 204)",
        entity_name="Feasibility Protocol Evaluation Authority"
    )
    secret_key = keypair["secret_key_b64"]

    trials_data = []
    issuance_times = []
    proof_gen_times = []
    verification_times = []
    workflow_times = []

    print(f"Starting execution of {num_trials} trials...")
    tracemalloc.start()
    t_start_all = time.perf_counter()

    for trial in range(1, num_trials + 1):
        # Step A: Generate Verifier Nonce for Replay Protection
        nonce_packet = VerificationService.create_verifier_nonce(validity_seconds=300)
        nonce = nonce_packet["verifier_nonce"]

        # Step B: Issuance & ML-DSA-65 Signing
        t_iss_0 = time.perf_counter()
        cred = CredentialService.issue_credential(
            issuer=issuer,
            subject_did=f"did:xeno:subject:trial_{trial:04d}",
            attributes=attributes,
            secret_key_b64=secret_key,
            bind_envelope=True
        )
        t_iss_1 = time.perf_counter()
        issuance_ms = (t_iss_1 - t_iss_0) * 1000

        cred_obj = IssuedCredential.objects.get(id=cred["credential_id"])

        # Step C: Client-Side Selective Disclosure Proof Extraction
        t_prf_0 = time.perf_counter()
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=cred_obj,
            disclosed_keys=disclosed_keys,
            verifier_nonce=nonce
        )
        t_prf_1 = time.perf_counter()
        proof_gen_ms = (t_prf_1 - t_prf_0) * 1000

        # Step D: Complete Verifier 5-Stage Pipeline
        t_ver_0 = time.perf_counter()
        ver_result = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_did=proof_packet["issuer_did"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"],
            subject_did=proof_packet["subject_did"],
            schema_id=proof_packet["schema_id"],
            verifier_nonce=proof_packet["verifier_nonce"],
            timestamp_iso=proof_packet["timestamp_iso"],
            replay_token=proof_packet["replay_token"]
        )
        t_ver_1 = time.perf_counter()
        verification_ms = (t_ver_1 - t_ver_0) * 1000

        total_workflow_ms = issuance_ms + proof_gen_ms + verification_ms

        valid = ver_result.get("valid", False)
        assert valid, f"Trial {trial} failed verification: {ver_result.get('error')}"

        issuance_times.append(issuance_ms)
        proof_gen_times.append(proof_gen_ms)
        verification_times.append(verification_ms)
        workflow_times.append(total_workflow_ms)

        trials_data.append({
            "trial": trial,
            "issuance_ms": round(issuance_ms, 3),
            "proof_gen_ms": round(proof_gen_ms, 3),
            "verification_ms": round(verification_ms, 3),
            "total_workflow_ms": round(total_workflow_ms, 3),
            "valid": valid
        })

        if trial % 10 == 0 or trial == num_trials:
            print(f"  [Progress] Trial {trial:3d}/{num_trials} completed | Workflow: {total_workflow_ms:7.2f} ms (Issuance: {issuance_ms:6.2f} ms, Proof: {proof_gen_ms:5.2f} ms, Verify: {verification_ms:5.2f} ms)")

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    t_end_all = time.perf_counter()
    total_elapsed_s = t_end_all - t_start_all

    # 2. Write raw CSV output
    with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["trial", "issuance_ms", "proof_gen_ms", "verification_ms", "total_workflow_ms", "valid"])
        writer.writeheader()
        writer.writerows(trials_data)

    print(f"\n[+] Raw dataset successfully written to: {output_csv}")

    # 3. Compute statistical distributions
    stats_issuance = calculate_statistics(issuance_times)
    stats_proof = calculate_statistics(proof_gen_times)
    stats_verification = calculate_statistics(verification_times)
    stats_workflow = calculate_statistics(workflow_times)

    print("\n" + "=" * 90)
    print("EMPIRICAL FEASIBILITY PROTOCOL SUMMARY (N = 100 TRIALS)")
    print("=" * 90)
    headers = ["Operation", "N", "Mean (ms)", "Std Dev", "Median (p50)", "p95 (ms)", "Min (ms)", "Max (ms)", "95% CI"]
    print(f"{headers[0]:<22} {headers[1]:<5} {headers[2]:<11} {headers[3]:<10} {headers[4]:<13} {headers[5]:<10} {headers[6]:<10} {headers[7]:<10} {headers[8]:<14}")
    print("-" * 105)

    def print_row(name, s):
        ci_str = f"± {s['ci_95']} ms"
        print(f"{name:<22} {s['n']:<5} {s['mean']:<11.2f} {s['std']:<10.2f} {s['p50']:<13.2f} {s['p95']:<10.2f} {s['min']:<10.2f} {s['max']:<10.2f} {ci_str:<14}")

    print_row("Issuance & Sign", stats_issuance)
    print_row("Proof Extraction", stats_proof)
    print_row("Verification", stats_verification)
    print_row("Total Workflow", stats_workflow)
    print("-" * 105)
    print(f"Total Execution Time: {total_elapsed_s:.2f} seconds | Peak Heap Allocation: {peak_mem / (1024 * 1024):.2f} MB")
    print(f"Success Rate: 100.0% ({num_trials}/{num_trials} verified)")
    print("=" * 90)

    return {
        "num_trials": num_trials,
        "total_elapsed_seconds": round(total_elapsed_s, 2),
        "peak_memory_mb": round(peak_mem / (1024 * 1024), 2),
        "issuance": stats_issuance,
        "proof_extraction": stats_proof,
        "verification": stats_verification,
        "total_workflow": stats_workflow
    }


if __name__ == "__main__":
    trials = 100
    if len(sys.argv) > 1:
        try:
            trials = int(sys.argv[1])
        except ValueError:
            pass
    run_feasibility_protocol(num_trials=trials)
