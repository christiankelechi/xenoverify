#!/usr/bin/env python3
"""
Comparative Cryptographic Benchmarking Protocol Runner (Protocol: xeno-merkle-mldsa-v2).
Compares NIST FIPS 204 ML-DSA-65 (dilithium-py pure Python) against Classical ECDSA secp256k1
(cryptography OpenSSL C backend):
- 5 discarded warm-up rounds per scheme
- 50 measured sequential trials per scheme (key generation, signing UTF-8(M), verification)
- High-resolution monotonic clock (time.perf_counter())
- Per-trial and overall Python-managed heap allocation via tracemalloc
- Exact raw vs DER/Base64/compact UTF-8 JSON packet byte measurements with explicit field lists

Outputs:
- docs/latest/comparative_benchmark_results.csv
- docs/latest/comparative_benchmark_results.json
"""

import csv
import json
import math
import os
import statistics
import sys
import time
import tracemalloc
import uuid
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend_django.settings")

import django
django.setup()

from cryptography.hazmat.primitives import serialization
from core_identity.crypto_service import PQCService, ECDSABaselineService
from core_identity.merkle_engine import (
    PROTOCOL_VERSION,
    SelectiveDisclosureEngine,
    compute_authenticated_envelope_message,
    build_replay_protection_token,
)
from run_feasibility_100 import collect_environment_metadata


def compute_distribution(values):
    """Sample SD (N-1), Median, Linear-Interpolation p95 at 0.95*(N-1), Nearest-Rank p95, and 95% Student-t CI."""
    n = len(values)
    mean_val = statistics.mean(values)
    std_val = statistics.stdev(values) if n > 1 else 0.0
    s = sorted(values)
    p50_val = statistics.median(s)

    pos = 0.95 * (n - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    p95_linear = s[lo] + (pos - lo) * (s[hi] - s[lo])
    p95_nearest = s[min(int(math.ceil(0.95 * n)) - 1, n - 1)]

    t_crit = 2.010 if n == 50 else (1.984 if n >= 60 else 2.093)
    ci_margin = t_crit * (std_val / math.sqrt(n)) if n > 1 else 0.0

    return {
        "n": n,
        "mean_ms": round(mean_val, 3),
        "std_ms": round(std_val, 3),
        "median_ms": round(p50_val, 3),
        "p95_linear_ms": round(p95_linear, 3),
        "p95_nearest_ms": round(p95_nearest, 3),
        "min_ms": round(s[0], 3),
        "max_ms": round(s[-1], 3),
        "ci_95_ms": round(ci_margin, 3),
    }


def compute_mem_distribution(byte_values):
    n = len(byte_values)
    mean_b = statistics.mean(byte_values)
    max_b = max(byte_values)
    min_b = min(byte_values)
    med_b = statistics.median(byte_values)
    return {
        "n": n,
        "mean_bytes": round(mean_b, 1),
        "mean_mib": round(mean_b / 1048576.0, 4),
        "median_bytes": round(med_b, 1),
        "median_mib": round(med_b / 1048576.0, 4),
        "min_bytes": int(min_b),
        "max_bytes": int(max_b),
        "max_mib": round(max_b / 1048576.0, 4),
    }


def measure_packet_footprints(attributes, disclosed_keys):
    """Measures exact raw, DER/Base64, and compact UTF-8 JSON payload sizes for both schemes."""
    commitment = SelectiveDisclosureEngine.create_credential_commitment(attributes)
    root = commitment["merkle_root"]
    cred_id = "cred-benchmark-001"
    issuer_did = "did:xeno:issuer:nimc-01"
    subject_did = "did:xeno:subject:001"
    schema_id = "urn:xeno:schema:id-credential:v1"

    m_digest, _ = compute_authenticated_envelope_message(
        issuer_did=issuer_did,
        credential_id=cred_id,
        subject_did=subject_did,
        merkle_root=root,
        schema_id=schema_id,
    )
    payload_bytes = m_digest.encode("utf-8")
    proof = SelectiveDisclosureEngine.generate_disclosure_proof(commitment["leaves"], disclosed_keys)
    nonce = "a" * 32
    ts = "2026-11-19T00:00:00+00:00"
    tok = build_replay_protection_token(cred_id, nonce, ts, disclosed_keys)

    pqc_kp = PQCService.generate_keypair()
    pqc_sig = PQCService.sign(payload_bytes, pqc_kp["secret_key_b64"])

    ec_kp = ECDSABaselineService.generate_keypair()
    ec_sig = ECDSABaselineService.sign(payload_bytes, ec_kp["secret_key_b64"])

    # ECDSA uncompressed point is 65 bytes (0x04 || x || y) -> raw affine coordinates = 64 bytes
    import base64
    ec_pk_obj = serialization.load_der_public_key(base64.b64decode(ec_kp["public_key_b64"]))
    ec_uncompressed = ec_pk_obj.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    def build_packets(scheme_name, pk_b64, sig_b64):
        full_cred = {
            "protocol_version": PROTOCOL_VERSION,
            "credential_id": cred_id,
            "subject_did": subject_did,
            "issuer_did": issuer_did,
            "schema_id": schema_id,
            "merkle_root": root,
            "envelope_message": m_digest,
            "signature_scheme": scheme_name,
            "signature_b64": sig_b64,
            "attributes": attributes,
            "leaves": commitment["leaves"],
        }
        pres_with_pk = {
            "protocol_version": PROTOCOL_VERSION,
            "credential_id": cred_id,
            "subject_did": subject_did,
            "issuer_did": issuer_did,
            "issuer_public_key_b64": pk_b64,
            "schema_id": schema_id,
            "merkle_root": root,
            "envelope_message": m_digest,
            "signature_scheme": scheme_name,
            "signature_b64": sig_b64,
            "disclosed_claims": proof["disclosed_claims"],
            "verifier_nonce": nonce,
            "timestamp_iso": ts,
            "replay_token": tok,
        }
        pres_registry = {k: v for k, v in pres_with_pk.items() if k != "issuer_public_key_b64"}

        def sz(obj):
            return len(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

        return {
            "full_credential_json_bytes": sz(full_cred),
            "full_credential_fields": list(full_cred.keys()),
            "presentation_registry_resolved_json_bytes": sz(pres_registry),
            "presentation_registry_resolved_fields": list(pres_registry.keys()),
            "presentation_with_public_key_json_bytes": sz(pres_with_pk),
            "presentation_with_public_key_fields": list(pres_with_pk.keys()),
            "public_key_b64_chars": len(pk_b64),
            "signature_b64_chars": len(sig_b64),
        }

    pqc_pkts = build_packets(PQCService.SCHEME_NAME, pqc_kp["public_key_b64"], pqc_sig["signature_b64"])
    ec_pkts = build_packets(ECDSABaselineService.SCHEME_NAME, ec_kp["public_key_b64"], ec_sig["signature_b64"])

    return {
        "serialization_convention": "Compact UTF-8 JSON using json.dumps(..., separators=(',', ':'), ensure_ascii=False).encode('utf-8') on 6-attribute Alex Carter fixture with 2/6 attributes disclosed (fullName, nationality).",
        "ml_dsa_65": {
            "public_key_raw_bytes": pqc_kp["public_key_bytes"],
            "secret_key_raw_bytes": pqc_kp["secret_key_bytes"],
            "signature_raw_bytes": pqc_sig["signature_bytes"],
            **pqc_pkts,
        },
        "ecdsa_secp256k1": {
            "public_key_raw_coords_bytes": len(ec_uncompressed) - 1,
            "public_key_uncompressed_sec1_bytes": len(ec_uncompressed),
            "public_key_spki_der_bytes": ec_kp["public_key_bytes"],
            "secret_key_raw_scalar_bytes": 32,
            "secret_key_pkcs8_der_bytes": ec_kp["secret_key_bytes"],
            "signature_raw_rs_bytes": 64,
            "signature_asn1_der_bytes_observed": ec_sig["signature_bytes"],
            **ec_pkts,
        },
    }


def run_comparative_benchmark(iterations=50, warmup=5, memory_profile_trials=10, output_dir=None):
    if output_dir is None:
        output_dir = os.path.join(PROJECT_ROOT, "docs", "latest")
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "comparative_benchmark_results.csv")
    json_path = os.path.join(output_dir, "comparative_benchmark_results.json")

    run_id = f"comp-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"
    env_meta = collect_environment_metadata()

    print("=" * 90)
    print(f"XENOVERIFY COMPARATIVE CRYPTOGRAPHIC BENCHMARK ({PROTOCOL_VERSION})")
    print(
        f"Run ID: {run_id} | Warm-ups: {warmup}/scheme | "
        f"Timing (tracemalloc OFF): {iterations}/scheme | Memory pass: {memory_profile_trials}/scheme"
    )
    print(f"Host: {env_meta['hardware']['model']} | {env_meta['hardware']['cpu']} | {env_meta['hardware']['ram_gb']} GB RAM")
    print("=" * 90)

    attributes = {
        "fullName": "Alex Carter",
        "nin": "29837492812",
        "dob": "1992-06-14",
        "nationality": "Nigerian",
        "clearanceLevel": "Tier-3",
        "residence": "Victoria Island, Lagos",
    }
    disclosed_keys = ["fullName", "nationality"]

    commitment = SelectiveDisclosureEngine.create_credential_commitment(attributes)
    m_digest, _ = compute_authenticated_envelope_message(
        issuer_did="did:xeno:issuer:nimc-01",
        credential_id="cred-benchmark-001",
        subject_did="did:xeno:subject:001",
        merkle_root=commitment["merkle_root"],
        schema_id="urn:xeno:schema:id-credential:v1",
    )
    payload_bytes = m_digest.encode("utf-8")

    # 1. Warm-up phase (excluded; tracemalloc OFF)
    print(f"\n[1/4] Executing {warmup} discarded warm-up rounds per scheme...")
    for _ in range(warmup):
        pkp = PQCService.generate_keypair()
        psg = PQCService.sign(payload_bytes, pkp["secret_key_b64"])
        assert PQCService.verify(payload_bytes, psg["signature_b64"], pkp["public_key_b64"])["valid"]

        ekp = ECDSABaselineService.generate_keypair()
        esg = ECDSABaselineService.sign(payload_bytes, ekp["secret_key_b64"])
        assert ECDSABaselineService.verify(payload_bytes, esg["signature_b64"], ekp["public_key_b64"])["valid"]

    # 2. Profile ML-DSA-65 pure timing (tracemalloc OFF)
    print(f"\n[2/4] Profiling NIST FIPS 204 ML-DSA-65 ({iterations} uninstrumented trials)...")
    pqc_keygen_ms, pqc_sign_ms, pqc_verify_ms = [], [], []
    pqc_bench_kp = PQCService.generate_keypair()

    for i in range(1, iterations + 1):
        t0 = time.perf_counter()
        _ = PQCService.generate_keypair()
        t1 = time.perf_counter()
        pqc_keygen_ms.append((t1 - t0) * 1000.0)

        t0 = time.perf_counter()
        sig = PQCService.sign(payload_bytes, pqc_bench_kp["secret_key_b64"])
        t1 = time.perf_counter()
        pqc_sign_ms.append((t1 - t0) * 1000.0)

        t0 = time.perf_counter()
        v = PQCService.verify(payload_bytes, sig["signature_b64"], pqc_bench_kp["public_key_b64"])
        t1 = time.perf_counter()
        assert v["valid"], f"ML-DSA-65 verify failed at trial {i}"
        pqc_verify_ms.append((t1 - t0) * 1000.0)

        if i % 10 == 0 or i == iterations:
            print(f"  [ML-DSA-65 {i:2d}/{iterations}] keygen={pqc_keygen_ms[-1]:.2f} ms | sign={pqc_sign_ms[-1]:.2f} ms | verify={pqc_verify_ms[-1]:.2f} ms")

    # 3. Profile Classical ECDSA secp256k1 pure timing (tracemalloc OFF)
    print(f"\n[3/4] Profiling Classical ECDSA secp256k1 ({iterations} uninstrumented trials)...")
    ecdsa_keygen_ms, ecdsa_sign_ms, ecdsa_verify_ms = [], [], []
    ecdsa_bench_kp = ECDSABaselineService.generate_keypair()

    for i in range(1, iterations + 1):
        t0 = time.perf_counter()
        _ = ECDSABaselineService.generate_keypair()
        t1 = time.perf_counter()
        ecdsa_keygen_ms.append((t1 - t0) * 1000.0)

        t0 = time.perf_counter()
        sig = ECDSABaselineService.sign(payload_bytes, ecdsa_bench_kp["secret_key_b64"])
        t1 = time.perf_counter()
        ecdsa_sign_ms.append((t1 - t0) * 1000.0)

        t0 = time.perf_counter()
        v = ECDSABaselineService.verify(payload_bytes, sig["signature_b64"], ecdsa_bench_kp["public_key_b64"])
        t1 = time.perf_counter()
        assert v["valid"], f"ECDSA verify failed at trial {i}"
        ecdsa_verify_ms.append((t1 - t0) * 1000.0)

        if i % 10 == 0 or i == iterations:
            print(f"  [ECDSA     {i:2d}/{iterations}] keygen={ecdsa_keygen_ms[-1]:.2f} ms | sign={ecdsa_sign_ms[-1]:.2f} ms | verify={ecdsa_verify_ms[-1]:.2f} ms")

    # 4. Isolated tracemalloc profiling pass per scheme
    print(f"\n[4/4] Isolated tracemalloc heap pass ({memory_profile_trials} trials per scheme)...")
    pqc_peak_bytes, pqc_inst_total_ms = [], []
    ecdsa_peak_bytes, ecdsa_inst_total_ms = [], []

    tracemalloc.start()
    try:
        pqc_baseline_mem, _ = tracemalloc.get_traced_memory()
        for i in range(1, memory_profile_trials + 1):
            tracemalloc.reset_peak()
            t0 = time.perf_counter()
            _ = PQCService.generate_keypair()
            sig = PQCService.sign(payload_bytes, pqc_bench_kp["secret_key_b64"])
            v = PQCService.verify(payload_bytes, sig["signature_b64"], pqc_bench_kp["public_key_b64"])
            assert v["valid"], f"ML-DSA-65 memory trial {i} failed"
            pqc_inst_total_ms.append((time.perf_counter() - t0) * 1000.0)
            _, peak_b = tracemalloc.get_traced_memory()
            pqc_peak_bytes.append(int(peak_b))

        ecdsa_baseline_mem, _ = tracemalloc.get_traced_memory()
        for i in range(1, memory_profile_trials + 1):
            tracemalloc.reset_peak()
            t0 = time.perf_counter()
            _ = ECDSABaselineService.generate_keypair()
            sig = ECDSABaselineService.sign(payload_bytes, ecdsa_bench_kp["secret_key_b64"])
            v = ECDSABaselineService.verify(payload_bytes, sig["signature_b64"], ecdsa_bench_kp["public_key_b64"])
            assert v["valid"], f"ECDSA memory trial {i} failed"
            ecdsa_inst_total_ms.append((time.perf_counter() - t0) * 1000.0)
            _, peak_b = tracemalloc.get_traced_memory()
            ecdsa_peak_bytes.append(int(peak_b))
    finally:
        tracemalloc.stop()

    print(f"  ML-DSA-65 peak Python heap: max={max(pqc_peak_bytes):,} B ({max(pqc_peak_bytes)/1048576.0:.3f} MiB)")
    print(f"  ECDSA     peak Python heap: max={max(ecdsa_peak_bytes):,} B ({max(ecdsa_peak_bytes)/1048576.0:.3f} MiB)")

    # Write raw pure-timing CSV (tracemalloc OFF)
    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "trial",
            "pqc_keygen_ms", "pqc_sign_ms", "pqc_verify_ms",
            "ecdsa_keygen_ms", "ecdsa_sign_ms", "ecdsa_verify_ms",
        ])
        for i in range(iterations):
            writer.writerow([
                i + 1,
                round(pqc_keygen_ms[i], 3),
                round(pqc_sign_ms[i], 3),
                round(pqc_verify_ms[i], 3),
                round(ecdsa_keygen_ms[i], 3),
                round(ecdsa_sign_ms[i], 3),
                round(ecdsa_verify_ms[i], 3),
            ])

    footprints = measure_packet_footprints(attributes, disclosed_keys)
    pqc_uninst_total_mean = statistics.mean([pqc_keygen_ms[i] + pqc_sign_ms[i] + pqc_verify_ms[i] for i in range(iterations)])
    ecdsa_uninst_total_mean = statistics.mean([ecdsa_keygen_ms[i] + ecdsa_sign_ms[i] + ecdsa_verify_ms[i] for i in range(iterations)])
    pqc_inst_total_mean = statistics.mean(pqc_inst_total_ms)
    ecdsa_inst_total_mean = statistics.mean(ecdsa_inst_total_ms)

    payload = {
        "benchmark_metadata": {
            "run_id": run_id,
            "date_utc": datetime.now(timezone.utc).isoformat(),
            "protocol_version": PROTOCOL_VERSION,
            "call_path": "Direct cryptographic service invocations over 64-byte UTF-8(M)",
            "key_reuse_policy": "Fresh keypair measured per trial for keygen; single pre-generated benchmark keypair reused across the 50 sign/verify iterations per scheme",
            "iterations": iterations,
            "warmup_rounds": warmup,
            "timing_instrumentation": "tracemalloc DISABLED during all 50 measured timing iterations per scheme",
            "pqc_standard": "NIST FIPS 204 (ML-DSA-65 via dilithium-py)",
            "classical_baseline": "ECDSA (secp256k1 / SHA-256 via cryptography/OpenSSL)",
            "statistics_config": {
                "sd_divisor": "N-1 (sample standard deviation)",
                "percentile_estimator": "Linear interpolation at zero-based index 0.95 * (N - 1) (nearest-rank also stored)",
                "confidence_interval": "Student's t two-tailed 95% CI (t_crit = 2.010 for df=49)",
            },
            "memory_tracing": {
                "tool": "Isolated Python tracemalloc pass (reset_peak() per trial; measures Python-managed heap only; excludes native OpenSSL C heap allocations and OS RSS)",
                "isolated_profile_trials_per_scheme": memory_profile_trials,
                "pqc_baseline_before_loop_bytes": pqc_baseline_mem,
                "ecdsa_baseline_before_loop_bytes": ecdsa_baseline_mem,
                "pqc_trial_peak_bytes": pqc_peak_bytes,
                "ecdsa_trial_peak_bytes": ecdsa_peak_bytes,
                "pqc_uninstrumented_total_mean_ms": round(pqc_uninst_total_mean, 3),
                "pqc_instrumented_total_mean_ms": round(pqc_inst_total_mean, 3),
                "pqc_tracemalloc_overhead_factor": round(pqc_inst_total_mean / pqc_uninst_total_mean, 2),
                "ecdsa_uninstrumented_total_mean_ms": round(ecdsa_uninst_total_mean, 3),
                "ecdsa_instrumented_total_mean_ms": round(ecdsa_inst_total_mean, 3),
                "ecdsa_tracemalloc_overhead_factor": round(ecdsa_inst_total_mean / ecdsa_uninst_total_mean, 2),
            },
            "environment": env_meta,
        },
        "footprint_comparison": footprints,
        "ml_dsa_65_distributions": {
            "keygen": compute_distribution(pqc_keygen_ms),
            "sign": compute_distribution(pqc_sign_ms),
            "verify": compute_distribution(pqc_verify_ms),
            "traced_python_heap_memory": compute_mem_distribution(pqc_peak_bytes),
        },
        "ecdsa_distributions": {
            "keygen": compute_distribution(ecdsa_keygen_ms),
            "sign": compute_distribution(ecdsa_sign_ms),
            "verify": compute_distribution(ecdsa_verify_ms),
            "traced_python_heap_memory": compute_mem_distribution(ecdsa_peak_bytes),
        },
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"\n[+] Saved {csv_path}")
    print(f"[+] Saved {json_path}")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    run_comparative_benchmark(iterations=n)
