"""
Service Layer for Selective Disclosure Proof Generation and Cryptographic Verification.
"""

import time
from typing import Dict, Any, List

from core_identity.models import IssuedCredential
from core_identity.merkle_engine import SelectiveDisclosureEngine
from core_identity.crypto_service import PQCService, ECDSABaselineService


class VerificationService:
    """
    Dedicated verifier engine evaluating Merkle proofs, quantum signatures, and revocation status.
    """

    @classmethod
    def generate_disclosure_proof(cls, credential: IssuedCredential, disclosed_keys: List[str]) -> Dict[str, Any]:
        """
        Extracts Merkle inclusion path for chosen claims.
        """
        t0 = time.perf_counter()
        proof_packet = SelectiveDisclosureEngine.generate_disclosure_proof(
            all_leaves=credential.leaves_json,
            disclosed_keys=disclosed_keys
        )
        generation_time_ms = (time.perf_counter() - t0) * 1000

        return {
            "credential_id": str(credential.id),
            "issuer_did": credential.issuer.did,
            "issuer_public_key_b64": credential.issuer.public_key_b64,
            "merkle_root": credential.merkle_root,
            "signature_scheme": credential.signature_scheme,
            "signature_b64": credential.signature_b64,
            "signature_bytes": credential.signature_bytes,
            "disclosed_claims": proof_packet["disclosed_claims"],
            "disclosed_count": proof_packet["disclosed_count"],
            "total_attributes": proof_packet["total_attributes"],
            "proof_generation_time_ms": round(generation_time_ms, 3)
        }

    @classmethod
    def verify_proof_package(
        cls,
        merkle_root: str,
        signature_b64: str,
        issuer_pk_b64: str,
        signature_scheme: str,
        disclosed_claims: List[Dict[str, Any]],
        credential_id: str = None
    ) -> Dict[str, Any]:
        """
        Executes complete verification pipeline:
        1. Ledger Revocation check
        2. Merkle Tree inclusion verification
        3. NIST FIPS 204 ML-DSA-65 signature validation
        """
        t0 = time.perf_counter()

        # 1. Revocation Check
        if credential_id:
            try:
                cred = IssuedCredential.objects.get(id=credential_id)
                if cred.is_revoked:
                    return {
                        "valid": False,
                        "error_stage": "REVOCATION_CHECK",
                        "error": f"Credential revoked: {cred.revocation_reason or 'Compromised'}"
                    }
            except IssuedCredential.DoesNotExist:
                pass

        # 2. Merkle Inclusion Check
        t_m0 = time.perf_counter()
        merkle_res = SelectiveDisclosureEngine.verify_disclosure_proof(merkle_root, disclosed_claims)
        t_m_ms = (time.perf_counter() - t_m0) * 1000

        if not merkle_res["valid"]:
            return {
                "valid": False,
                "error_stage": "MERKLE_PROOF_INCLUSION",
                "error": merkle_res.get("error"),
                "failed_attribute": merkle_res.get("failed_attribute"),
                "merkle_verification_time_ms": round(t_m_ms, 3)
            }

        # 3. Signature Verification
        t_s0 = time.perf_counter()
        if "ECDSA" in signature_scheme:
            sig_res = ECDSABaselineService.verify(merkle_root.encode("utf-8"), signature_b64, issuer_pk_b64)
        else:
            sig_res = PQCService.verify(merkle_root.encode("utf-8"), signature_b64, issuer_pk_b64)
        t_s_ms = (time.perf_counter() - t_s0) * 1000

        if not sig_res["valid"]:
            return {
                "valid": False,
                "error_stage": "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION",
                "error": sig_res.get("error", "Signature verification failed"),
                "merkle_verification_time_ms": round(t_m_ms, 3),
                "signature_verification_time_ms": round(t_s_ms, 3)
            }

        total_verification_time_ms = (time.perf_counter() - t0) * 1000

        return {
            "valid": True,
            "status": "CRYPTOGRAPHICALLY_VERIFIED",
            "verified_attributes": merkle_res["verified_attributes"],
            "disclosed_count": len(merkle_res["verified_attributes"]),
            "merkle_root": merkle_root,
            "signature_scheme": signature_scheme,
            "metrics": {
                "merkle_proof_verification_ms": round(t_m_ms, 3),
                "signature_verification_ms": round(t_s_ms, 3),
                "total_workflow_verification_ms": round(total_verification_time_ms, 3)
            }
        }
