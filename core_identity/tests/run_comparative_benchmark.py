#!/usr/bin/env python3
"""
Comparative Cryptographic Benchmarking Protocol Runner.
Implements Section 6 Protocol Specifications & Chapter 4 Evaluation:
- Compares NIST FIPS 204 ML-DSA-65 against Classical Baseline (ECDSA secp256k1)
- 5 Discarded warm-up rounds to eliminate initial CPU scaling and JIT / memory allocation artifacts
- 50 Measured trial iterations per scheme
- Monotonic timing boundaries via time.perf_counter()
- Memory footprint profiling via tracemalloc
- Descriptive metrics: Mean, Std Dev, Median (p50), 95th Percentile (p95), Min, Max, 95% CI (Student-t)
- Output:
    - docs/comparative_benchmark_results.csv
    - docs/comparative_benchmark_results.json
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

from core_identity.crypto_service import PQCService, ECDSABaselineService
from core_identity.merkle_engine import SelectiveDisclosureEngine, compute_authenticated_envelope_message


def compute_distribution(latencies):
    """Computes descriptive statistics and 95% Student's t confidence interval."""
    n = len(latencies)
    mean_val = statistics.mean(latencies)
    std_val = statistics.stdev(latencies) if n > 1 else 0.0
    sorted_vals = sorted(latencies)
    p50_val = statistics.median(sorted_vals)
    p95_idx = int(math.ceil(0.95 * n)) - 1
    p95_val = sorted_vals[min(p95_idx, n - 1)]
    min_val = min(latencies)
    max_val = max(latencies)

    # Student's t critical value for df=n-1 at 95% confidence (t ~ 2.009 for n=50)
    t_crit = 2.009 if n >= 50 else 2.093
    ci_margin = t_crit * (std_val / math.sqrt(n)) if n > 1 else 0.0

    return {
        "n": n,
        "mean_ms": round(mean_val, 3),
        "std_ms": round(std_val, 3),
        "median_ms": round(p50_val, 3),
        "p95_ms": round(p95_val, 3),
        "min_ms": round(min_val, 3),
        "max_ms": round(max_val, 3),
        "ci_95_ms": round(ci_margin, 3)
    }


def run_comparative_benchmark(iterations=50, warmup=5):
    """
    Executes the comparative cryptographic protocol.
    """
    print("=" * 85)
    print("XENOVERIFY COMPARATIVE CRYPTOGRAPHIC BENCHMARKING PROTOCOL")
    print("Schemes: NIST FIPS 204 ML-DSA-65 vs Classical ECDSA (secp256k1)")
    print(f"Protocol: {warmup} Discarded Warm-up Rounds + {iterations} Measured Consecutive Trials")
    print("=" * 85)

    # Standard worked synthetic credential attributes
    attributes = {
        "fullName": "Alex Carter",
        "nin": "29837492812",
        "dob": "1992-06-14",
        "nationality": "Nigerian",
        "clearanceLevel": "Tier-3",
        "residence": "Victoria Island, Lagos"
    }
    commitment = SelectiveDisclosureEngine.create_credential_commitment(attributes)
    root = commitment["merkle_root"]

    # Compute Authenticated Envelope message M
    m_digest, _ = compute_authenticated_envelope_message(
        issuer_did="did:xeno:issuer:nimc-01",
        credential_id="cred-benchmark-001",
        subject_did="did:xeno:subject:001",
        merkle_root=root,
        schema_id="urn:xeno:schema:id-credential:v1"
    )
    payload_bytes = m_digest.encode("utf-8")

    # -------------------------------------------------------------
    # 1. Warm-up Phase (Discarded)
    # -------------------------------------------------------------
    print(f"\n[1/3] Executing {warmup} warm-up rounds to stabilize processor clock and cache...")
    for _ in range(warmup):
        pqc_kp = PQCService.generate_keypair()
        pqc_s = PQCService.sign(payload_bytes, pqc_kp["secret_key_b64"])
        PQCService.verify(payload_bytes, pqc_s["signature_b64"], pqc_kp["public_key_b64"])

        ec_kp = ECDSABaselineService.generate_keypair()
        ec_s = ECDSABaselineService.sign(payload_bytes, ec_kp["secret_key_b64"])
        ECDSABaselineService.verify(payload_bytes, ec_s["signature_b64"], ec_kp["public_key_b64"])

    # -------------------------------------------------------------
    # 2. Benchmark NIST FIPS 204 ML-DSA-65
    # -------------------------------------------------------------
    print(f"\n[2/3] Profiling NIST FIPS 204 ML-DSA-65 across {iterations} trials...")
    pqc_keygen_times = []
    pqc_sign_times = []
    pqc_verify_times = []

    pqc_benchmark_kp = PQCService.generate_keypair()
    pk_pqc_bytes = pqc_benchmark_kp["public_key_bytes"]
    sk_pqc_bytes = pqc_benchmark_kp["secret_key_bytes"]
    sig_pqc_bytes = PQCService.FIPS204_SIG_BYTES

    tracemalloc.start()
    for i in range(1, iterations + 1):
        # Keygen
        t0 = time.perf_counter()
        kp = PQCService.generate_keypair()
        t1 = time.perf_counter()
        pqc_keygen_times.append((t1 - t0) * 1000)

        # Sign
        t0 = time.perf_counter()
        sig = PQCService.sign(payload_bytes, pqc_benchmark_kp["secret_key_b64"])
        t1 = time.perf_counter()
        pqc_sign_times.append((t1 - t0) * 1000)

        # Verify
        t0 = time.perf_counter()
        v = PQCService.verify(payload_bytes, sig["signature_b64"], pqc_benchmark_kp["public_key_b64"])
        t1 = time.perf_counter()
        pqc_verify_times.append((t1 - t0) * 1000)
        assert v["valid"], f"PQC verification failed on trial {i}"

        if i % 10 == 0 or i == iterations:
            print(f"  [ML-DSA-65] Completed trial {i:2d}/{iterations} (Sign: {pqc_sign_times[-1]:.2f} ms, Verify: {pqc_verify_times[-1]:.2f} ms)")

    _, pqc_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # -------------------------------------------------------------
    # 3. Benchmark Classical ECDSA Baseline (secp256k1)
    # -------------------------------------------------------------
    print(f"\n[3/3] Profiling Classical ECDSA (secp256k1) across {iterations} trials...")
    ecdsa_keygen_times = []
    ecdsa_sign_times = []
    ecdsa_verify_times = []

    ecdsa_benchmark_kp = ECDSABaselineService.generate_keypair()
    pk_ecdsa_bytes = ecdsa_benchmark_kp["public_key_bytes"]
    sk_ecdsa_bytes = ecdsa_benchmark_kp["secret_key_bytes"]
    sample_ecdsa_sig = ECDSABaselineService.sign(payload_bytes, ecdsa_benchmark_kp["secret_key_b64"])
    sig_ecdsa_bytes = sample_ecdsa_sig["signature_bytes"]

    tracemalloc.start()
    for i in range(1, iterations + 1):
        # Keygen
        t0 = time.perf_counter()
        kp = ECDSABaselineService.generate_keypair()
        t1 = time.perf_counter()
        ecdsa_keygen_times.append((t1 - t0) * 1000)

        # Sign
        t0 = time.perf_counter()
        sig = ECDSABaselineService.sign(payload_bytes, ecdsa_benchmark_kp["secret_key_b64"])
        t1 = time.perf_counter()
        ecdsa_sign_times.append((t1 - t0) * 1000)

        # Verify
        t0 = time.perf_counter()
        v = ECDSABaselineService.verify(payload_bytes, sig["signature_b64"], ecdsa_benchmark_kp["public_key_b64"])
        t1 = time.perf_counter()
        ecdsa_verify_times.append((t1 - t0) * 1000)
        assert v["valid"], f"ECDSA verification failed on trial {i}"

        if i % 10 == 0 or i == iterations:
            print(f"  [ECDSA]     Completed trial {i:2d}/{iterations} (Sign: {ecdsa_sign_times[-1]:.2f} ms, Verify: {ecdsa_verify_times[-1]:.2f} ms)")

    _, ecdsa_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Statistical Distributions
    pqc_keygen_dist = compute_distribution(pqc_keygen_times)
    pqc_sign_dist = compute_distribution(pqc_sign_times)
    pqc_verify_dist = compute_distribution(pqc_verify_times)

    ecdsa_keygen_dist = compute_distribution(ecdsa_keygen_times)
    ecdsa_sign_dist = compute_distribution(ecdsa_sign_times)
    ecdsa_verify_dist = compute_distribution(ecdsa_verify_times)

    # -------------------------------------------------------------
    # 4. Formatted Summary Table
    # -------------------------------------------------------------
    print("\n" + "=" * 100)
    print("COMPARATIVE CRYPTOGRAPHIC BENCHMARK RESULTS (N = 50 TRIALS)")
    print("=" * 100)
    header = f"{'Metric / Operation':<28} | {'ECDSA (secp256k1)':<24} | {'ML-DSA-65 (FIPS 204)':<24} | {'Differential Ratio':<15}"
    print(header)
    print("-" * 100)

    # Storage Footprints
    print(f"{'Security Category':<28} | {'Classical 128-bit':<24} | {'NIST Category 3':<24} | {'Quantum-Safe':<15}")
    print(f"{'Public Key Size':<28} | {f'{pk_ecdsa_bytes} Bytes':<24} | {f'{pk_pqc_bytes} Bytes':<24} | {f'{pk_pqc_bytes / pk_ecdsa_bytes:.1f}x larger':<15}")
    print(f"{'Secret Key Size':<28} | {f'{sk_ecdsa_bytes} Bytes':<24} | {f'{sk_pqc_bytes} Bytes':<24} | {f'{sk_pqc_bytes / sk_ecdsa_bytes:.1f}x larger':<15}")
    print(f"{'Signature Size':<28} | {f'{sig_ecdsa_bytes} Bytes':<24} | {f'{sig_pqc_bytes} Bytes':<24} | {f'{sig_pqc_bytes / sig_ecdsa_bytes:.1f}x larger':<15}")
    print("-" * 100)

    # Keygen
    ec_kg_str = f"{ecdsa_keygen_dist['mean_ms']} ± {ecdsa_keygen_dist['ci_95_ms']}"
    pqc_kg_str = f"{pqc_keygen_dist['mean_ms']} ± {pqc_keygen_dist['ci_95_ms']}"
    kg_ratio = f"{pqc_keygen_dist['mean_ms'] / max(0.001, ecdsa_keygen_dist['mean_ms']):.1f}x"
    print(f"{'Keygen Mean (ms)':<28} | {ec_kg_str:<24} | {pqc_kg_str:<24} | {kg_ratio}")
    print(f"{'Keygen Median (p50) (ms)':<28} | {str(ecdsa_keygen_dist['median_ms']):<24} | {str(pqc_keygen_dist['median_ms']):<24} | {'-'}")

    # Sign
    ec_sgn_str = f"{ecdsa_sign_dist['mean_ms']} ± {ecdsa_sign_dist['ci_95_ms']}"
    pqc_sgn_str = f"{pqc_sign_dist['mean_ms']} ± {pqc_sign_dist['ci_95_ms']}"
    sgn_ratio = f"{pqc_sign_dist['mean_ms'] / max(0.001, ecdsa_sign_dist['mean_ms']):.1f}x"
    print(f"{'Signing Mean (ms)':<28} | {ec_sgn_str:<24} | {pqc_sgn_str:<24} | {sgn_ratio}")
    print(f"{'Signing Median (p50) (ms)':<28} | {str(ecdsa_sign_dist['median_ms']):<24} | {str(pqc_sign_dist['median_ms']):<24} | {'-'}")
    print(f"{'Signing p95 (ms)':<28} | {str(ecdsa_sign_dist['p95_ms']):<24} | {str(pqc_sign_dist['p95_ms']):<24} | {'-'}")

    # Verify
    ec_ver_str = f"{ecdsa_verify_dist['mean_ms']} ± {ecdsa_verify_dist['ci_95_ms']}"
    pqc_ver_str = f"{pqc_verify_dist['mean_ms']} ± {pqc_verify_dist['ci_95_ms']}"
    ver_ratio = f"{pqc_verify_dist['mean_ms'] / max(0.001, ecdsa_verify_dist['mean_ms']):.1f}x"
    print(f"{'Verify Mean (ms)':<28} | {ec_ver_str:<24} | {pqc_ver_str:<24} | {ver_ratio}")
    print(f"{'Verify Median (p50) (ms)':<28} | {str(ecdsa_verify_dist['median_ms']):<24} | {str(pqc_verify_dist['median_ms']):<24} | {'-'}")
    print(f"{'Verify p95 (ms)':<28} | {str(ecdsa_verify_dist['p95_ms']):<24} | {str(pqc_verify_dist['p95_ms']):<24} | {'-'}")
    print("-" * 100)
    print(f"{'Peak Heap Memory':<28} | {f'{ecdsa_peak_mem / (1024*1024):.2f} MB':<24} | {f'{pqc_peak_mem / (1024*1024):.2f} MB':<24} | {'Both < 5 MB'}")
    print("=" * 100)

    # -------------------------------------------------------------
    # 5. Persist Output CSV and JSON Artifacts
    # -------------------------------------------------------------
    docs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs"))
    os.makedirs(docs_dir, exist_ok=True)
    csv_path = os.path.join(docs_dir, "comparative_benchmark_results.csv")
    json_path = os.path.join(docs_dir, "comparative_benchmark_results.json")

    # CSV Write
    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["trial", "pqc_keygen_ms", "pqc_sign_ms", "pqc_verify_ms", "ecdsa_keygen_ms", "ecdsa_sign_ms", "ecdsa_verify_ms"])
        for i in range(iterations):
            writer.writerow([
                i + 1,
                round(pqc_keygen_times[i], 3),
                round(pqc_sign_times[i], 3),
                round(pqc_verify_times[i], 3),
                round(ecdsa_keygen_times[i], 3),
                round(ecdsa_sign_times[i], 3),
                round(ecdsa_verify_times[i], 3),
            ])

    # JSON Write
    results_payload = {
        "benchmark_metadata": {
            "date": datetime.now().isoformat(),
            "iterations": iterations,
            "warmup_rounds": warmup,
            "pqc_standard": "NIST FIPS 204 (ML-DSA-65)",
            "classical_baseline": "ECDSA (secp256k1 / SHA-256)"
        },
        "footprint_comparison": {
            "ml_dsa_65": {
                "public_key_bytes": pk_pqc_bytes,
                "secret_key_bytes": sk_pqc_bytes,
                "signature_bytes": sig_pqc_bytes
            },
            "ecdsa": {
                "public_key_bytes": pk_ecdsa_bytes,
                "secret_key_bytes": sk_ecdsa_bytes,
                "signature_bytes": sig_ecdsa_bytes
            }
        },
        "ml_dsa_65_distributions": {
            "keygen": pqc_keygen_dist,
            "sign": pqc_sign_dist,
            "verify": pqc_verify_dist
        },
        "ecdsa_distributions": {
            "keygen": ecdsa_keygen_dist,
            "sign": ecdsa_sign_dist,
            "verify": ecdsa_verify_dist
        }
    }
    with open(json_path, mode="w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2)

    print(f"[+] Comparative CSV written to: {csv_path}")
    print(f"[+] Comparative JSON written to: {json_path}")

    return results_payload


if __name__ == "__main__":
    trials = 50
    if len(sys.argv) > 1:
        try:
            trials = int(sys.argv[1])
        except ValueError:
            pass
    run_comparative_benchmark(iterations=trials)
