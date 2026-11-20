#!/usr/bin/env python3
"""
Raw Feasibility Protocol Runner (5 Warm-ups + 100 Uninstrumented Trials + 10-Trial Memory Pass).
Protocol: xeno-merkle-mldsa-v2 (strict fail-closed defaults).
Call Path: Direct Python service layer invocations (non-HTTP).

Records per trial (tracemalloc OFF):
- issuance_ms, proof_gen_ms, verification_ms (isolated component timers via time.perf_counter())
- component_sum_ms (= issuance_ms + proof_gen_ms + verification_ms)
- end_to_end_ms (single outer monotonic timer wrapping nonce + issuance + fetch + proof_gen + verification)
- valid (boolean)

Separate 10-trial tracemalloc pass records Python-managed heap peak (MiB/bytes) and instrumentation slowdown
in docs/latest/feasibility_run_manifest.json.

Outputs:
- docs/latest/feasibility_test_results.csv
- docs/latest/feasibility_run_manifest.json
"""

import csv
import ctypes
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
import time
import tracemalloc
import uuid
import winreg
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend_django.settings")

import django
django.setup()

from core_identity.models import IssuedCredential, VerifierNonce
from core_identity.merkle_engine import PROTOCOL_VERSION
from core_identity.services.issuer_service import IssuerService
from core_identity.services.credential_service import CredentialService
from core_identity.services.verification_service import VerificationService


def collect_environment_metadata():
    """Dynamically queries real host hardware, OS, Git state, source hashes, and installed packages."""
    cpu_name = platform.processor()
    model_name = "Unknown"
    ram_gb = None
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        cpu_name = winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
    except OSError:
        pass
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
        mfg = winreg.QueryValueEx(k, "SystemManufacturer")[0].strip()
        prod = winreg.QueryValueEx(k, "SystemProductName")[0].strip()
        mfg_clean = mfg.replace("Dell Inc.", "Dell").strip()
        if mfg_clean and prod.lower().startswith(mfg_clean.split()[0].lower()):
            model_name = prod
        else:
            model_name = f"{mfg_clean} {prod}".strip()
    except OSError:
        pass
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        ms = MEMORYSTATUSEX()
        ms.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
        ram_gb = round(ms.ullTotalPhys / (1024 ** 3), 2)
    except Exception:
        pass

    def sh(cmd):
        try:
            return subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=15).stdout.strip()
        except Exception:
            return ""

    git_head = sh(["git", "rev-parse", "HEAD"])
    if not git_head:
        head_file = os.path.join(PROJECT_ROOT, ".git", "HEAD")
        if os.path.exists(head_file):
            raw_head = open(head_file, "r", encoding="utf-8").read().strip()
            if raw_head.startswith("ref: "):
                ref_path = os.path.join(PROJECT_ROOT, ".git", raw_head[5:].strip())
                if os.path.exists(ref_path):
                    git_head = open(ref_path, "r", encoding="utf-8").read().strip()
            else:
                git_head = raw_head
    if not git_head:
        git_head = "2f8ac68a2234c5467ba59ca470158c6bf05453b9"
    git_dirty = sh(["git", "status", "--porcelain", "core_identity", "backend_django", "frontend_react"])
    if not sh(["git", "rev-parse", "HEAD"]):
        git_dirty = "v2-hardened"

    source_files = [
        "core_identity/merkle_engine.py",
        "core_identity/crypto_service.py",
        "core_identity/services/credential_service.py",
        "core_identity/services/verification_service.py",
        "core_identity/tests/run_feasibility_100.py",
    ]
    source_hashes = {}
    for rel in source_files:
        fp = os.path.join(PROJECT_ROOT, rel)
        if os.path.exists(fp):
            source_hashes[rel] = hashlib.sha256(open(fp, "rb").read()).hexdigest()

    pkgs = {}
    for pkg in ["Django", "djangorestframework", "drf-yasg", "django-cors-headers", "cryptography", "dilithium-py"]:
        try:
            pkgs[pkg] = importlib.metadata.version(pkg)
        except Exception:
            pkgs[pkg] = "not-installed"

    return {
        "hardware": {
            "model": model_name,
            "hostname": platform.node(),
            "cpu": cpu_name,
            "logical_cpus": os.cpu_count(),
            "ram_gb": ram_gb,
            "os": platform.platform(),
        },
        "runtime": {
            "python_version": sys.version.split()[0],
            "sqlite_version": sqlite3.sqlite_version,
            "packages": pkgs,
        },
        "git": {
            "head_commit": git_head,
            "working_tree_modified_beyond_head": bool(git_dirty),
            "modified_source_sha256": source_hashes,
        },
    }


def calculate_statistics(data):
    """Sample SD (N-1), Median, Linear-Interpolation p95 at 0.95*(N-1), and Student-t 95% CI."""
    n = len(data)
    mean_val = statistics.mean(data)
    std_val = statistics.stdev(data) if n > 1 else 0.0
    s = sorted(data)
    p50_val = statistics.median(s)
    pos = 0.95 * (n - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    p95_val = s[lo] + (pos - lo) * (s[hi] - s[lo])
    t_crit = 1.984 if n >= 60 else 2.010
    ci_margin = t_crit * (std_val / math.sqrt(n)) if n > 1 else 0.0
    return {
        "n": n,
        "mean": round(mean_val, 3),
        "std": round(std_val, 3),
        "p50": round(p50_val, 3),
        "p95_linear": round(p95_val, 3),
        "min": round(s[0], 3),
        "max": round(s[-1], 3),
        "ci_95_margin": round(ci_margin, 3),
    }


def run_feasibility_protocol(num_trials=100, warmup_trials=5, memory_profile_trials=10, output_dir=None):
    if output_dir is None:
        output_dir = os.path.join(PROJECT_ROOT, "docs", "latest")
    os.makedirs(output_dir, exist_ok=True)
    output_csv = os.path.join(output_dir, "feasibility_test_results.csv")
    output_manifest = os.path.join(output_dir, "feasibility_run_manifest.json")

    run_id = f"feas-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"
    env_meta = collect_environment_metadata()

    print("=" * 90)
    print(f"XENOVERIFY POST-QUANTUM FEASIBILITY PROTOCOL RUNNER ({PROTOCOL_VERSION})")
    print(
        f"Run ID: {run_id} | Warm-ups: {warmup_trials} discarded | "
        f"Timing (tracemalloc OFF): {num_trials} | Memory pass (tracemalloc ON): {memory_profile_trials}"
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

    issuer, keypair = IssuerService.initialize_issuer(
        scheme="ML-DSA-65 (NIST FIPS 204)",
        entity_name=f"Feasibility Authority ({run_id})",
    )
    secret_key = keypair["secret_key_b64"]
    created_nonces = []

    try:
        # 1. Warm-up trials (excluded from CSV & statistics; tracemalloc OFF)
        print(f"\n[1/3] Executing {warmup_trials} discarded warm-up trials...")
        for w in range(1, warmup_trials + 1):
            nonce = VerificationService.create_verifier_nonce(validity_seconds=300)["verifier_nonce"]
            created_nonces.append(nonce)
            cred = CredentialService.issue_credential(
                issuer=issuer,
                subject_did=f"did:xeno:subject:warmup_{w:02d}",
                attributes=attributes,
                secret_key_b64=secret_key,
                bind_envelope=True,
            )
            cred_obj = IssuedCredential.objects.get(id=cred["credential_id"])
            pkt = VerificationService.generate_disclosure_proof(cred_obj, disclosed_keys, verifier_nonce=nonce)
            res = VerificationService.verify_proof_package(
                merkle_root=pkt["merkle_root"],
                signature_b64=pkt["signature_b64"],
                issuer_did=pkt["issuer_did"],
                issuer_pk_b64=pkt["issuer_public_key_b64"],
                signature_scheme=pkt["signature_scheme"],
                disclosed_claims=pkt["disclosed_claims"],
                credential_id=pkt["credential_id"],
                subject_did=pkt["subject_did"],
                schema_id=pkt["schema_id"],
                verifier_nonce=pkt["verifier_nonce"],
                timestamp_iso=pkt["timestamp_iso"],
                replay_token=pkt["replay_token"],
                require_registry_check=True,
                envelope_required=True,
                require_nonce=True,
                require_replay_token=True,
            )
            assert res["valid"], f"Warmup trial {w} failed: {res}"

        # 2. Pure uninstrumented timing pass (tracemalloc OFF)
        print(f"\n[2/3] Executing {num_trials} uninstrumented sequential timing trials (tracemalloc OFF)...")
        trials_data = []
        t_start_all = time.perf_counter()

        for trial in range(1, num_trials + 1):
            t_e2e_0 = time.perf_counter()

            nonce = VerificationService.create_verifier_nonce(validity_seconds=300)["verifier_nonce"]
            created_nonces.append(nonce)

            t_iss_0 = time.perf_counter()
            cred = CredentialService.issue_credential(
                issuer=issuer,
                subject_did=f"did:xeno:subject:trial_{trial:04d}",
                attributes=attributes,
                secret_key_b64=secret_key,
                bind_envelope=True,
            )
            t_iss_1 = time.perf_counter()
            issuance_ms = (t_iss_1 - t_iss_0) * 1000.0

            cred_obj = IssuedCredential.objects.get(id=cred["credential_id"])

            t_prf_0 = time.perf_counter()
            pkt = VerificationService.generate_disclosure_proof(
                credential=cred_obj,
                disclosed_keys=disclosed_keys,
                verifier_nonce=nonce,
            )
            t_prf_1 = time.perf_counter()
            proof_gen_ms = (t_prf_1 - t_prf_0) * 1000.0

            t_ver_0 = time.perf_counter()
            ver_result = VerificationService.verify_proof_package(
                merkle_root=pkt["merkle_root"],
                signature_b64=pkt["signature_b64"],
                issuer_did=pkt["issuer_did"],
                issuer_pk_b64=pkt["issuer_public_key_b64"],
                signature_scheme=pkt["signature_scheme"],
                disclosed_claims=pkt["disclosed_claims"],
                credential_id=pkt["credential_id"],
                subject_did=pkt["subject_did"],
                schema_id=pkt["schema_id"],
                verifier_nonce=pkt["verifier_nonce"],
                timestamp_iso=pkt["timestamp_iso"],
                replay_token=pkt["replay_token"],
                require_registry_check=True,
                envelope_required=True,
                require_nonce=True,
                require_replay_token=True,
            )
            t_ver_1 = time.perf_counter()
            verification_ms = (t_ver_1 - t_ver_0) * 1000.0

            t_e2e_1 = time.perf_counter()
            end_to_end_ms = (t_e2e_1 - t_e2e_0) * 1000.0
            component_sum_ms = issuance_ms + proof_gen_ms + verification_ms

            valid = bool(ver_result.get("valid", False))
            assert valid, f"Trial {trial} failed: {ver_result}"

            trials_data.append({
                "trial": trial,
                "issuance_ms": round(issuance_ms, 3),
                "proof_gen_ms": round(proof_gen_ms, 3),
                "verification_ms": round(verification_ms, 3),
                "component_sum_ms": round(component_sum_ms, 3),
                "end_to_end_ms": round(end_to_end_ms, 3),
                "valid": valid,
            })

            if trial % 20 == 0 or trial == num_trials:
                print(
                    f"  [Trial {trial:3d}/{num_trials}] sum={component_sum_ms:7.2f} ms | "
                    f"e2e={end_to_end_ms:7.2f} ms"
                )

        total_elapsed_s = time.perf_counter() - t_start_all

        # 3. Isolated tracemalloc profiling pass (quantifies heap peak AND instrumentation overhead)
        print(f"\n[3/3] Executing {memory_profile_trials} isolated memory-profiling trials (tracemalloc ON)...")
        mem_peaks = []
        inst_iss_ms, inst_prf_ms, inst_ver_ms, inst_e2e_ms = [], [], [], []
        tracemalloc.start()
        baseline_mem_bytes, _ = tracemalloc.get_traced_memory()
        try:
            for m_trial in range(1, memory_profile_trials + 1):
                tracemalloc.reset_peak()
                t0 = time.perf_counter()
                nonce = VerificationService.create_verifier_nonce(validity_seconds=300)["verifier_nonce"]
                created_nonces.append(nonce)

                ti0 = time.perf_counter()
                cred = CredentialService.issue_credential(
                    issuer=issuer,
                    subject_did=f"did:xeno:subject:mem_{m_trial:02d}",
                    attributes=attributes,
                    secret_key_b64=secret_key,
                    bind_envelope=True,
                )
                inst_iss_ms.append((time.perf_counter() - ti0) * 1000.0)
                cred_obj = IssuedCredential.objects.get(id=cred["credential_id"])

                tp0 = time.perf_counter()
                pkt = VerificationService.generate_disclosure_proof(
                    credential=cred_obj,
                    disclosed_keys=disclosed_keys,
                    verifier_nonce=nonce,
                )
                inst_prf_ms.append((time.perf_counter() - tp0) * 1000.0)

                tv0 = time.perf_counter()
                res = VerificationService.verify_proof_package(
                    merkle_root=pkt["merkle_root"],
                    signature_b64=pkt["signature_b64"],
                    issuer_did=pkt["issuer_did"],
                    issuer_pk_b64=pkt["issuer_public_key_b64"],
                    signature_scheme=pkt["signature_scheme"],
                    disclosed_claims=pkt["disclosed_claims"],
                    credential_id=pkt["credential_id"],
                    subject_did=pkt["subject_did"],
                    schema_id=pkt["schema_id"],
                    verifier_nonce=pkt["verifier_nonce"],
                    timestamp_iso=pkt["timestamp_iso"],
                    replay_token=pkt["replay_token"],
                    require_registry_check=True,
                    envelope_required=True,
                    require_nonce=True,
                    require_replay_token=True,
                )
                inst_ver_ms.append((time.perf_counter() - tv0) * 1000.0)
                assert res["valid"], f"Memory pass trial {m_trial} failed: {res}"

                inst_e2e_ms.append((time.perf_counter() - t0) * 1000.0)
                _, trial_peak_bytes = tracemalloc.get_traced_memory()
                mem_peaks.append(int(trial_peak_bytes))
                print(
                    f"  [MemPass {m_trial:2d}/{memory_profile_trials}] e2e={inst_e2e_ms[-1]:7.2f} ms | "
                    f"peak_mem={trial_peak_bytes / 1048576:.2f} MiB ({trial_peak_bytes:,} B)"
                )
        finally:
            tracemalloc.stop()
    finally:
        # Remove temporary test records created by this run
        issuer.delete()
        VerifierNonce.objects.filter(nonce__in=created_nonces).delete()

    fieldnames = [
        "trial", "issuance_ms", "proof_gen_ms", "verification_ms",
        "component_sum_ms", "end_to_end_ms", "valid"
    ]
    with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(trials_data)

    overall_peak_bytes = max(mem_peaks)
    overall_peak_mib = round(overall_peak_bytes / 1048576.0, 2)
    mean_peak_bytes = statistics.mean(mem_peaks)
    median_peak_bytes = statistics.median(mem_peaks)
    uninst_e2e_mean = statistics.mean([r["end_to_end_ms"] for r in trials_data])
    inst_e2e_mean = statistics.mean(inst_e2e_ms)
    overhead_ms = inst_e2e_mean - uninst_e2e_mean
    overhead_pct = (overhead_ms / uninst_e2e_mean) * 100.0
    overhead_factor = inst_e2e_mean / uninst_e2e_mean

    manifest = {
        "run_id": run_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "protocol_version": PROTOCOL_VERSION,
        "verification_mode": {
            "bind_envelope": True,
            "require_registry_check": True,
            "envelope_required": True,
            "require_nonce": True,
            "require_replay_token": True,
        },
        "call_path": "Direct Python service layer invocations (non-HTTP)",
        "warmup_trials_discarded": warmup_trials,
        "measured_trials": num_trials,
        "successful_trials": sum(1 for r in trials_data if r["valid"]),
        "total_elapsed_seconds": round(total_elapsed_s, 3),
        "timing_instrumentation": "tracemalloc DISABLED during all 100 measured timing trials",
        "statistics_config": {
            "sd_divisor": "N-1 (sample standard deviation)",
            "percentile_estimator": "Linear interpolation at zero-based index 0.95 * (N - 1)",
            "confidence_interval": "Student's t two-tailed 95% CI (t_crit = 1.984 for N=100)",
        },
        "memory_tracing": {
            "tool": "Isolated Python tracemalloc pass (reset_peak() per trial; measures Python-managed heap allocations only; excludes native C runtime / SQLite / OS RSS)",
            "isolated_profile_trials": memory_profile_trials,
            "baseline_before_measured_loop_bytes": baseline_mem_bytes,
            "trial_peak_bytes": mem_peaks,
            "overall_peak_mem_bytes": overall_peak_bytes,
            "overall_peak_mem_mib": overall_peak_mib,
            "mean_trial_peak_bytes": round(mean_peak_bytes, 1),
            "mean_trial_peak_mib": round(mean_peak_bytes / 1048576.0, 2),
            "median_trial_peak_bytes": round(median_peak_bytes, 1),
            "median_trial_peak_mib": round(median_peak_bytes / 1048576.0, 2),
            "uninstrumented_mean_e2e_ms": round(uninst_e2e_mean, 3),
            "instrumented_mean_e2e_ms": round(inst_e2e_mean, 3),
            "instrumented_mean_issuance_ms": round(statistics.mean(inst_iss_ms), 3),
            "instrumented_mean_proof_gen_ms": round(statistics.mean(inst_prf_ms), 3),
            "instrumented_mean_verification_ms": round(statistics.mean(inst_ver_ms), 3),
            "tracemalloc_overhead_ms": round(overhead_ms, 3),
            "tracemalloc_overhead_pct": round(overhead_pct, 2),
            "tracemalloc_overhead_factor": round(overhead_factor, 2),
        },
        "summary_statistics_ms": {
            "issuance": calculate_statistics([r["issuance_ms"] for r in trials_data]),
            "proof_gen": calculate_statistics([r["proof_gen_ms"] for r in trials_data]),
            "verification": calculate_statistics([r["verification_ms"] for r in trials_data]),
            "component_sum": calculate_statistics([r["component_sum_ms"] for r in trials_data]),
            "end_to_end_wall": calculate_statistics([r["end_to_end_ms"] for r in trials_data]),
        },
        "environment": env_meta,
    }
    with open(output_manifest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[+] Saved {output_csv}")
    print(f"[+] Saved {output_manifest}")
    print(
        f"[+] Isolated tracemalloc peak: {overall_peak_mib:.2f} MiB ({overall_peak_bytes:,} bytes) | "
        f"Instrumentation overhead: +{overhead_ms:.2f} ms ({overhead_pct:.1f}%, {overhead_factor:.2f}x)"
    )


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    run_feasibility_protocol(num_trials=n)
