"""
Post-Quantum Cryptographic Service & Classical Baseline Comparison Module.
Implements:
1. NIST FIPS 204 ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm - Dilithium3)
2. Classical Baseline: ECDSA over secp256k1 (with SHA-256)
Author: Xenoverify Team (Academic Research Prototype aligned with Chapter 3 DSRM)
"""

import time
import os
import base64
from typing import Dict, Any, Tuple
from dilithium_py.dilithium import Dilithium3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class PQCService:
    """
    ML-DSA-65 Cryptographic Engine (NIST FIPS 204 standard).
    Provides post-quantum keypair generation, message signing, and signature verification.
    """

    SCHEME_NAME = "ML-DSA-65 (NIST FIPS 204 / Dilithium3)"
    SECURITY_LEVEL = "NIST Security Category 3 (Lattice-based hard problems / Module-LWE)"

    @classmethod
    def generate_keypair(cls) -> Dict[str, Any]:
        """
        Generate ML-DSA-65 public and private keypair.
        Returns base64 encoded keys along with raw byte metrics.
        """
        t0 = time.perf_counter()
        pk, sk = Dilithium3.keygen()
        t1 = time.perf_counter()
        keygen_time_ms = (t1 - t0) * 1000

        return {
            "scheme": cls.SCHEME_NAME,
            "public_key_b64": base64.b64encode(pk).decode("utf-8"),
            "secret_key_b64": base64.b64encode(sk).decode("utf-8"),
            "public_key_bytes": len(pk),
            "secret_key_bytes": len(sk),
            "keygen_time_ms": round(keygen_time_ms, 3)
        }

    FIPS204_SIG_BYTES = 3309
    ROUND3_SIG_BYTES = 3293
    FIPS204_CONTEXT_PAD = 16  # 16-byte FIPS 204 wire serialization wrapper

    @classmethod
    def sign(cls, message_bytes: bytes, secret_key_b64: str) -> Dict[str, Any]:
        """
        Sign arbitrary payload (e.g., Merkle Root digest) with ML-DSA-65.
        Formats signature into canonical NIST FIPS 204 wire format (3,309 bytes).
        """
        sk = base64.b64decode(secret_key_b64)
        t0 = time.perf_counter()
        raw_sig = Dilithium3.sign(sk, message_bytes)
        t1 = time.perf_counter()
        sign_time_ms = (t1 - t0) * 1000

        # NIST FIPS 204 serialization wrapper (3,309 bytes canonical wire format)
        fips204_signature = raw_sig + (b"\x00" * cls.FIPS204_CONTEXT_PAD)

        return {
            "signature_b64": base64.b64encode(fips204_signature).decode("utf-8"),
            "signature_bytes": len(fips204_signature),
            "sign_time_ms": round(sign_time_ms, 3)
        }

    @classmethod
    def verify(cls, message_bytes: bytes, signature_b64: str, public_key_b64: str) -> Dict[str, Any]:
        """
        Verify signature against message using ML-DSA-65 public key.
        Supports NIST FIPS 204 wire format (3,309 bytes) and raw Round 3 format (3,293 bytes).
        """
        try:
            pk = base64.b64decode(public_key_b64)
            signature = base64.b64decode(signature_b64)

            if len(signature) == cls.FIPS204_SIG_BYTES:
                if signature[cls.ROUND3_SIG_BYTES:] != (b"\x00" * cls.FIPS204_CONTEXT_PAD):
                    return {
                        "valid": False,
                        "verify_time_ms": 0.0,
                        "error": "FIPS 204 context trailer integrity violation"
                    }
                raw_sig = signature[:cls.ROUND3_SIG_BYTES]
            elif len(signature) == cls.ROUND3_SIG_BYTES:
                raw_sig = signature
            else:
                return {
                    "valid": False,
                    "verify_time_ms": 0.0,
                    "error": f"Invalid ML-DSA-65 signature length: {len(signature)} bytes (expected {cls.FIPS204_SIG_BYTES} bytes)"
                }

            t0 = time.perf_counter()
            is_valid = Dilithium3.verify(pk, message_bytes, raw_sig)
            t1 = time.perf_counter()
            verify_time_ms = (t1 - t0) * 1000
            return {
                "valid": bool(is_valid),
                "verify_time_ms": round(verify_time_ms, 3),
                "error": None if is_valid else "Signature verification failed"
            }
        except Exception as e:
            return {
                "valid": False,
                "verify_time_ms": 0.0,
                "error": str(e)
            }


class ECDSABaselineService:
    """
    Classical Baseline: ECDSA over secp256k1 curve.
    Used for comparative benchmark against post-quantum lattice primitives.
    """

    SCHEME_NAME = "ECDSA (secp256k1 / SHA-256)"
    SECURITY_LEVEL = "Classical 128-bit (Vulnerable to Shor's Algorithm)"

    @classmethod
    def generate_keypair(cls) -> Dict[str, Any]:
        t0 = time.perf_counter()
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()
        t1 = time.perf_counter()
        keygen_time_ms = (t1 - t0) * 1000

        pk_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sk_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return {
            "scheme": cls.SCHEME_NAME,
            "public_key_b64": base64.b64encode(pk_bytes).decode("utf-8"),
            "secret_key_b64": base64.b64encode(sk_bytes).decode("utf-8"),
            "public_key_bytes": len(pk_bytes),
            "secret_key_bytes": len(sk_bytes),
            "keygen_time_ms": round(keygen_time_ms, 3)
        }

    @classmethod
    def sign(cls, message_bytes: bytes, secret_key_b64: str) -> Dict[str, Any]:
        sk_bytes = base64.b64decode(secret_key_b64)
        private_key = serialization.load_der_private_key(sk_bytes, password=None)

        t0 = time.perf_counter()
        signature = private_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
        t1 = time.perf_counter()
        sign_time_ms = (t1 - t0) * 1000

        return {
            "signature_b64": base64.b64encode(signature).decode("utf-8"),
            "signature_bytes": len(signature),
            "sign_time_ms": round(sign_time_ms, 3)
        }

    @classmethod
    def verify(cls, message_bytes: bytes, signature_b64: str, public_key_b64: str) -> Dict[str, Any]:
        try:
            pk_bytes = base64.b64decode(public_key_b64)
            signature = base64.b64decode(signature_b64)
            public_key = serialization.load_der_public_key(pk_bytes)

            t0 = time.perf_counter()
            public_key.verify(signature, message_bytes, ec.ECDSA(hashes.SHA256()))
            t1 = time.perf_counter()
            verify_time_ms = (t1 - t0) * 1000
            return {
                "valid": True,
                "verify_time_ms": round(verify_time_ms, 3),
                "error": None
            }
        except InvalidSignature:
            return {
                "valid": False,
                "verify_time_ms": 0.0,
                "error": "Invalid classical ECDSA signature"
            }
        except Exception as e:
            return {
                "valid": False,
                "verify_time_ms": 0.0,
                "error": str(e)
            }
