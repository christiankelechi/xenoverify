"""
Post-Quantum Cryptographic Service & Classical Baseline Comparison Module.
Implements:
1. NIST FIPS 204 ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm)
2. Classical Baseline: ECDSA over secp256k1 (with SHA-256)
Author: Xenoverify Team (Academic Research Prototype aligned with Chapter 3 DSRM)
"""

import time
import os
import base64
from typing import Dict, Any, Tuple
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class PQCService:
    """
    ML-DSA-65 Cryptographic Engine (NIST FIPS 204 final standard).
    Provides post-quantum keypair generation, message signing, and signature verification.
    Uses native FIPS 204 parameters:
      - Public Key: 1,952 bytes
      - Secret Key: 4,032 bytes
      - Signature: 3,309 bytes
    """

    SCHEME_NAME = "ML-DSA-65 (NIST FIPS 204)"
    SECURITY_LEVEL = "NIST Security Category 3 (Lattice-based hard problems / Module-LWE)"
    FIPS204_PK_BYTES = 1952
    FIPS204_SK_BYTES = 4032
    FIPS204_SIG_BYTES = 3309

    @classmethod
    def generate_keypair(cls) -> Dict[str, Any]:
        """
        Generate ML-DSA-65 public and private keypair per NIST FIPS 204.
        Returns base64 encoded keys along with raw byte metrics.
        """
        t0 = time.perf_counter()
        pk, sk = ML_DSA_65.keygen()
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

    @classmethod
    def sign(cls, message_bytes: bytes, secret_key_b64: str) -> Dict[str, Any]:
        """
        Sign arbitrary payload (e.g., Merkle Root digest or Authenticated Envelope Message M)
        with ML-DSA-65. Generates canonical NIST FIPS 204 signature (3,309 bytes).
        """
        sk = base64.b64decode(secret_key_b64)
        t0 = time.perf_counter()
        signature = ML_DSA_65.sign(sk, message_bytes)
        t1 = time.perf_counter()
        sign_time_ms = (t1 - t0) * 1000

        return {
            "signature_b64": base64.b64encode(signature).decode("utf-8"),
            "signature_bytes": len(signature),
            "sign_time_ms": round(sign_time_ms, 3)
        }

    @classmethod
    def verify(cls, message_bytes: bytes, signature_b64: str, public_key_b64: str) -> Dict[str, Any]:
        """
        Verify signature against message using ML-DSA-65 public key per NIST FIPS 204.
        Validates public key size (1,952 bytes) and signature size (3,309 bytes).
        """
        try:
            pk = base64.b64decode(public_key_b64)
            signature = base64.b64decode(signature_b64)

            if len(pk) != cls.FIPS204_PK_BYTES:
                return {
                    "valid": False,
                    "verify_time_ms": 0.0,
                    "error": f"Invalid ML-DSA-65 public key length: {len(pk)} bytes (expected {cls.FIPS204_PK_BYTES} bytes per NIST FIPS 204)"
                }

            if len(signature) != cls.FIPS204_SIG_BYTES:
                return {
                    "valid": False,
                    "verify_time_ms": 0.0,
                    "error": f"Invalid ML-DSA-65 signature length: {len(signature)} bytes (expected {cls.FIPS204_SIG_BYTES} bytes per NIST FIPS 204)"
                }

            t0 = time.perf_counter()
            is_valid = ML_DSA_65.verify(pk, message_bytes, signature)
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
