"""
Service Layer for Chapter 4 DSRM Benchmark Trials & Statistical Profiling.
"""

import statistics
from typing import Dict, Any, List

from core_identity.crypto_service import PQCService, ECDSABaselineService
from core_identity.merkle_engine import SelectiveDisclosureEngine


class BenchmarkService:
    """
    Executes controlled empirical trials profiling latency distributions and storage footprints.
    """

    DEFAULT_ATTRIBUTES = {
        "fullName": "Alex Carter",
        "nin": "28374928192",
        "dob": "1993-08-20",
        "nationality": "Nigerian",
        "stateOfOrigin": "Ondo",
        "bvn": "22938472819",
        "clearanceLevel": "Tier-3",
        "address": "Victoria Island, Lagos"
    }

    @staticmethod
    def _compute_distribution(latencies: List[float]) -> Dict[str, float]:
        """
        Computes Mean, Median, and p95 tail latencies for empirical evaluation.
        """
        sorted_vals = sorted(latencies)
        p95_idx = int(0.95 * len(sorted_vals))
        return {
            "mean_ms": round(statistics.mean(latencies), 3),
            "median_ms": round(statistics.median(latencies), 3),
            "p95_ms": round(sorted_vals[min(p95_idx, len(sorted_vals) - 1)], 3),
            "min_ms": round(min(latencies), 3),
            "max_ms": round(max(latencies), 3)
        }

    @classmethod
    def run_comparative_benchmark(cls, iterations: int = 20) -> Dict[str, Any]:
        """
        Runs automated comparative benchmark between ML-DSA-65 and ECDSA baseline.
        """
        iterations = max(5, min(iterations, 100))
        attrs = cls.DEFAULT_ATTRIBUTES

        # Merkle Commitment
        commitment = SelectiveDisclosureEngine.create_credential_commitment(attrs)
        root = commitment["merkle_root"]

        # 1. Profile ML-DSA-65
        pqc_keygen_times, pqc_sign_times, pqc_verify_times = [], [], []
        pqc_keys = PQCService.generate_keypair()

        for _ in range(iterations):
            kg = PQCService.generate_keypair()
            pqc_keygen_times.append(kg["keygen_time_ms"])
            s = PQCService.sign(root.encode("utf-8"), pqc_keys["secret_key_b64"])
            pqc_sign_times.append(s["sign_time_ms"])
            v = PQCService.verify(root.encode("utf-8"), s["signature_b64"], pqc_keys["public_key_b64"])
            pqc_verify_times.append(v["verify_time_ms"])

        # 2. Profile ECDSA Baseline
        ecdsa_keygen_times, ecdsa_sign_times, ecdsa_verify_times = [], [], []
        ecdsa_keys = ECDSABaselineService.generate_keypair()

        for _ in range(iterations):
            kg = ECDSABaselineService.generate_keypair()
            ecdsa_keygen_times.append(kg["keygen_time_ms"])
            s = ECDSABaselineService.sign(root.encode("utf-8"), ecdsa_keys["secret_key_b64"])
            ecdsa_sign_times.append(s["sign_time_ms"])
            v = ECDSABaselineService.verify(root.encode("utf-8"), s["signature_b64"], ecdsa_keys["public_key_b64"])
            ecdsa_verify_times.append(v["verify_time_ms"])

        return {
            "iterations": iterations,
            "attribute_count": len(attrs),
            "ml_dsa_65": {
                "scheme": "ML-DSA-65 (NIST FIPS 204)",
                "public_key_bytes": pqc_keys["public_key_bytes"],
                "signature_bytes": 3309,
                "keygen": cls._compute_distribution(pqc_keygen_times),
                "sign": cls._compute_distribution(pqc_sign_times),
                "verify": cls._compute_distribution(pqc_verify_times)
            },
            "ecdsa_baseline": {
                "scheme": "ECDSA (secp256k1)",
                "public_key_bytes": ecdsa_keys["public_key_bytes"],
                "signature_bytes": 71,
                "keygen": cls._compute_distribution(ecdsa_keygen_times),
                "sign": cls._compute_distribution(ecdsa_sign_times),
                "verify": cls._compute_distribution(ecdsa_verify_times)
            },
            "selective_disclosure_merkle": {
                "algorithm": "SHA-256 + 128-bit Salt per leaf",
                "leaves_count": len(attrs),
                "leaf_hash_size_bytes": 32,
                "merkle_root_hex": root
            }
        }
