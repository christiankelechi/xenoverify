"""
Service Layer for Credential Lifecycle & Merkle Commitments.
"""

import time
import uuid
from typing import Dict, Any, List
from django.db import transaction

from core_identity.models import DIDRegistry, IssuedCredential
from core_identity.merkle_engine import SelectiveDisclosureEngine, compute_authenticated_envelope_message
from core_identity.crypto_service import PQCService, ECDSABaselineService


class CredentialService:
    """
    Encapsulates credential issuance, Merkle-tree commitment generation,
    domain-separated envelope message synthesis, and post-quantum signing.
    """

    @classmethod
    @transaction.atomic
    def issue_credential(
        cls,
        issuer: DIDRegistry,
        subject_did: str,
        attributes: Dict[str, Any],
        secret_key_b64: str,
        schema_id: str = "urn:xeno:schema:id-credential:v1",
        bind_envelope: bool = False
    ) -> Dict[str, Any]:
        """
        1. Salts each credential attribute with 128-bit CSPRNG.
        2. Constructs Merkle commitment tree and computes root R.
        3. Computes domain-separated Authenticated Credential Envelope message M:
           M = SHA-256( schema_id || ':' || issuer_did || ':' || credential_id || ':' || subject_did || ':' || merkle_root )
        4. Signs either envelope digest M (if bind_envelope=True) or Merkle root R (if bind_envelope=False)
           with issuer's algorithm (NIST FIPS 204 ML-DSA-65 or ECDSA).
        5. Persists and returns complete verifiable credential entity.
        """
        t0 = time.perf_counter()
        cred_id = uuid.uuid4()
        commitment = SelectiveDisclosureEngine.create_credential_commitment(attributes)
        merkle_root = commitment["merkle_root"]

        # Compute Authenticated Credential Envelope message M (Section 2.2)
        envelope_digest, _ = compute_authenticated_envelope_message(
            issuer_did=issuer.did,
            credential_id=str(cred_id),
            subject_did=subject_did,
            merkle_root=merkle_root,
            schema_id=schema_id
        )

        # Determine signed payload: Envelope M or Root R
        if bind_envelope:
            payload_to_sign = envelope_digest.encode("utf-8")
        else:
            payload_to_sign = merkle_root.encode("utf-8")

        # Cryptographic signature
        if "ECDSA" in issuer.scheme:
            sig_res = ECDSABaselineService.sign(payload_to_sign, secret_key_b64)
        else:
            sig_res = PQCService.sign(payload_to_sign, secret_key_b64)

        issuance_time_ms = (time.perf_counter() - t0) * 1000

        cred = IssuedCredential.objects.create(
            id=cred_id,
            subject_did=subject_did,
            issuer=issuer,
            schema_id=schema_id,
            merkle_root=merkle_root,
            envelope_message=envelope_digest,
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
            "schema_id": schema_id,
            "merkle_root": merkle_root,
            "envelope_message": envelope_digest,
            "signed_target": "AUTHENTICATED_ENVELOPE" if bind_envelope else "MERKLE_ROOT",
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
