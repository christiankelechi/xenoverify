"""
Service Layer for Credential Lifecycle & Merkle Commitments.
"""

import time
import uuid
from typing import Dict, Any, List
from django.db import transaction

from core_identity.models import DIDRegistry, IssuedCredential
from core_identity.merkle_engine import SelectiveDisclosureEngine
from core_identity.crypto_service import PQCService, ECDSABaselineService


class CredentialService:
    """
    Encapsulates credential issuance, Merkle-tree commitment generation, and signing.
    """

    @classmethod
    @transaction.atomic
    def issue_credential(
        cls,
        issuer: DIDRegistry,
        subject_did: str,
        attributes: Dict[str, Any],
        secret_key_b64: str
    ) -> Dict[str, Any]:
        """
        1. Salts each credential attribute with 128-bit CSPRNG.
        2. Constructs Merkle commitment tree and computes root.
        3. Signs Merkle root with issuer's algorithm (ML-DSA-65 or ECDSA).
        4. Persists and returns complete verifiable credential entity.
        """
        t0 = time.perf_counter()
        commitment = SelectiveDisclosureEngine.create_credential_commitment(attributes)
        merkle_root = commitment["merkle_root"]

        # Cryptographic signature on Merkle Root
        if "ECDSA" in issuer.scheme:
            sig_res = ECDSABaselineService.sign(merkle_root.encode("utf-8"), secret_key_b64)
        else:
            sig_res = PQCService.sign(merkle_root.encode("utf-8"), secret_key_b64)

        issuance_time_ms = (time.perf_counter() - t0) * 1000

        cred = IssuedCredential.objects.create(
            subject_did=subject_did,
            issuer=issuer,
            merkle_root=merkle_root,
            signature_scheme=issuer.scheme,
            signature_b64=sig_res["signature_b64"],
            signature_bytes=sig_res["signature_bytes"],
            attributes_json=attributes,
            leaves_json=commitment["leaves"],
            attribute_count=len(commitment["leaves"])
        )

        return {
            "credential_id": str(cred.id),
            "subject_did": subject_did,
            "issuer_did": issuer.did,
            "merkle_root": merkle_root,
            "signature_scheme": issuer.scheme,
            "signature_b64": sig_res["signature_b64"],
            "signature_bytes": sig_res["signature_bytes"],
            "issuance_time_ms": round(issuance_time_ms, 3),
            "leaves": commitment["leaves"],
            "attributes": attributes
        }

    @classmethod
    def revoke_credential(cls, credential_id: str, reason: str = "") -> IssuedCredential:
        """
        Updates revocation status accumulator in simulated ledger.
        """
        cred = IssuedCredential.objects.get(id=credential_id)
        cred.is_revoked = True
        cred.revocation_reason = reason or "Holder revocation request / credential rotation"
        cred.save(update_fields=["is_revoked", "revocation_reason"])
        return cred
