"""
Service Layer for Selective Disclosure Proof Generation and Cryptographic Verification.
Implements the 5-Stage Verification Pipeline:
Stage 0: Presentation Replay Protection & Verifier Nonce Verification
Stage 1: Revocation Check against Simulated Ledger
Stage 2: Independent Issuer Registry Resolution & Public Key Authentication
Stage 3: Salted Binary Merkle Tree Inclusion Proof Verification
Stage 4: NIST FIPS 204 ML-DSA-65 Post-Quantum Signature Verification
          (Evaluating Authenticated Credential Envelope Message M and Root R)
"""

import time
import secrets
from datetime import timedelta
from typing import Dict, Any, List, Optional, Tuple
from django.utils import timezone
from django.core.exceptions import ValidationError

from core_identity.models import DIDRegistry, IssuedCredential, VerifierNonce
from core_identity.merkle_engine import (
    PROTOCOL_VERSION,
    SelectiveDisclosureEngine,
    compute_authenticated_envelope_message,
    build_replay_protection_token,
    verify_replay_protection_token,
)
from core_identity.crypto_service import PQCService, ECDSABaselineService


class VerificationService:
    """
    Dedicated verifier engine evaluating Replay Defense, Revocation,
    Issuer Registry authority, Merkle proofs, and NIST FIPS 204 signatures.
    """

    @classmethod
    def create_verifier_nonce(cls, validity_seconds: int = 300) -> Dict[str, Any]:
        """
        Generates a 128-bit CSPRNG challenge nonce for replay protection.
        Stored in VerifierNonce model with specified validity TTL (default 300s).
        """
        nonce = secrets.token_hex(16)
        expires_at = timezone.now() + timedelta(seconds=validity_seconds)
        obj = VerifierNonce.objects.create(
            nonce=nonce,
            expires_at=expires_at,
            is_consumed=False
        )
        return {
            "verifier_nonce": obj.nonce,
            "created_at": obj.created_at.isoformat(),
            "expires_at": obj.expires_at.isoformat(),
            "validity_seconds": validity_seconds
        }

    @classmethod
    def generate_disclosure_proof(
        cls,
        credential: IssuedCredential,
        disclosed_keys: List[str],
        verifier_nonce: Optional[str] = None,
        include_issuer_public_key: bool = True
    ) -> Dict[str, Any]:
        """
        Extracts Merkle inclusion path for chosen claims while withholding unselected attributes.
        Optionally generates and binds a presentation-level replay protection token.
        """
        t0 = time.perf_counter()
        proof_packet = SelectiveDisclosureEngine.generate_disclosure_proof(
            all_leaves=credential.leaves_json,
            disclosed_keys=disclosed_keys
        )
        generation_time_ms = (time.perf_counter() - t0) * 1000

        timestamp_iso = timezone.now().isoformat()
        replay_token = None
        if verifier_nonce:
            replay_token = build_replay_protection_token(
                credential_id=str(credential.id),
                verifier_nonce=verifier_nonce,
                timestamp_iso=timestamp_iso,
                disclosed_keys=disclosed_keys
            )

        packet = {
            "protocol_version": PROTOCOL_VERSION,
            "credential_id": str(credential.id),
            "subject_did": credential.subject_did,
            "issuer_did": credential.issuer.did,
            "schema_id": getattr(credential, "schema_id", "urn:xeno:schema:id-credential:v1"),
            "merkle_root": credential.merkle_root,
            "envelope_message": getattr(credential, "envelope_message", None),
            "signature_scheme": credential.signature_scheme,
            "signature_b64": credential.signature_b64,
            "signature_bytes": credential.signature_bytes,
            "disclosed_claims": proof_packet["disclosed_claims"],
            "disclosed_count": proof_packet["disclosed_count"],
            "total_attributes": proof_packet["total_attributes"],
            "verifier_nonce": verifier_nonce,
            "timestamp_iso": timestamp_iso,
            "replay_token": replay_token,
            "proof_generation_time_ms": round(generation_time_ms, 3)
        }
        if include_issuer_public_key:
            packet["issuer_public_key_b64"] = credential.issuer.public_key_b64
        return packet

    @classmethod
    def verify_proof_package(
        cls,
        merkle_root: str,
        signature_b64: str,
        issuer_pk_b64: Optional[str] = None,
        issuer_did: Optional[str] = None,
        signature_scheme: str = "ML-DSA-65",
        disclosed_claims: Optional[List[Dict[str, Any]]] = None,
        credential_id: Optional[str] = None,
        subject_did: Optional[str] = None,
        schema_id: str = "urn:xeno:schema:id-credential:v1",
        verifier_nonce: Optional[str] = None,
        timestamp_iso: Optional[str] = None,
        replay_token: Optional[str] = None,
        require_registry_check: bool = True,
        envelope_required: bool = True,
        require_nonce: bool = True,
        require_replay_token: bool = True
    ) -> Dict[str, Any]:
        """
        Executes complete fail-closed 5-stage verification pipeline (Protocol xeno-merkle-mldsa-v2):
        Stage 0: Replay Protection & Verifier Nonce Validation (atomic early consumption)
        Stage 1: Revocation Check against Simulated Ledger
        Stage 2: Independent Issuer Registry Resolution & Public Key Authentication
        Stage 3: Domain-Separated Salted Merkle Tree Inclusion Proof Verification
        Stage 4: NIST FIPS 204 ML-DSA-65 Signature Verification on Authenticated Envelope M
        """
        t0 = time.perf_counter()
        disclosed_claims = disclosed_claims or []
        disclosed_keys = [c.get("key") for c in disclosed_claims if isinstance(c, dict) and isinstance(c.get("key"), str)]

        # ---------------------------------------------------------
        # STAGE 0: Presentation Replay Protection & Nonce Validation
        # ---------------------------------------------------------
        if not verifier_nonce:
            if require_nonce:
                return {
                    "valid": False,
                    "error_stage": "REPLAY_PROTECTION",
                    "error": "Missing mandatory verifier challenge nonce in presentation payload"
                }
        else:
            now = timezone.now()
            # Conditional atomic UPDATE prevents concurrent double-spend race on VerifierNonce.
            # Trade-off (documented): Stage 0 consumes the nonce prior to Stage 3/4 signature checks,
            # so an invalid presentation consumes that single-use challenge and requires a fresh nonce.
            updated = VerifierNonce.objects.filter(
                nonce=verifier_nonce,
                is_consumed=False,
                expires_at__gt=now
            ).update(is_consumed=True, consumed_at=now)

            if updated == 0:
                nonce_obj = VerifierNonce.objects.filter(nonce=verifier_nonce).first()
                if not nonce_obj:
                    return {
                        "valid": False,
                        "error_stage": "REPLAY_PROTECTION",
                        "error": f"Invalid challenge nonce: verifier challenge nonce '{verifier_nonce}' not found or unissued"
                    }
                if nonce_obj.is_consumed:
                    return {
                        "valid": False,
                        "error_stage": "REPLAY_PROTECTION",
                        "error": f"Replay attack detected: verifier challenge nonce '{verifier_nonce}' already consumed"
                    }
                return {
                    "valid": False,
                    "error_stage": "REPLAY_PROTECTION",
                    "error": "Verifier challenge nonce has expired"
                }

            # Check cryptographic replay token challenge binding
            if not replay_token:
                if require_replay_token:
                    return {
                        "valid": False,
                        "error_stage": "REPLAY_PROTECTION",
                        "error": "Missing mandatory replay protection token for verifier challenge binding"
                    }
            else:
                valid_token = verify_replay_protection_token(
                    token=replay_token,
                    credential_id=credential_id or "",
                    verifier_nonce=verifier_nonce,
                    timestamp_iso=timestamp_iso or "",
                    disclosed_keys=disclosed_keys
                )
                if not valid_token:
                    return {
                        "valid": False,
                        "error_stage": "REPLAY_PROTECTION",
                        "error": "Replay protection token invalid: challenge nonce, timestamp, or disclosed claim mismatch"
                    }

        # ---------------------------------------------------------
        # STAGE 1: Revocation Accumulator Check (Simulated Ledger)
        # ---------------------------------------------------------
        cred = None
        if credential_id:
            try:
                cred = IssuedCredential.objects.select_related("issuer").get(id=credential_id)
                if cred.is_revoked:
                    return {
                        "valid": False,
                        "error_stage": "REVOCATION_CHECK",
                        "error": f"Credential revoked: {cred.revocation_reason or 'Compromised / Revoked'}"
                    }
                if not issuer_did:
                    issuer_did = cred.issuer.did
                if not subject_did:
                    subject_did = cred.subject_did
                if not schema_id:
                    schema_id = cred.schema_id
            except (IssuedCredential.DoesNotExist, ValueError, ValidationError):
                cred = None

        # ---------------------------------------------------------
        # STAGE 2: Independent Issuer Registry Resolution & Authentication
        # ---------------------------------------------------------
        if not issuer_did:
            return {
                "valid": False,
                "error_stage": "ISSUER_REGISTRY_VERIFICATION",
                "error": "Missing mandatory issuer DID: verifier cannot independently resolve public key authority"
            }

        issuer_record = DIDRegistry.objects.filter(did=issuer_did, is_active=True).first()
        if not issuer_record:
            return {
                "valid": False,
                "error_stage": "ISSUER_REGISTRY_VERIFICATION",
                "error": f"Untrusted issuer: DID '{issuer_did}' not registered or inactive in DID Registry"
            }

        # Crucial Security Check: Presenter must not substitute their own public key
        if issuer_pk_b64 and issuer_pk_b64 != issuer_record.public_key_b64:
            return {
                "valid": False,
                "error_stage": "ISSUER_REGISTRY_VERIFICATION",
                "error": "Presented public key does not match the anchored public key in DID Registry (Key substitution rejected)"
            }

        trusted_pk_b64 = issuer_record.public_key_b64
        resolved_scheme = issuer_record.scheme

        # ---------------------------------------------------------
        # STAGE 3: Merkle Inclusion Proof Reconciliation
        # ---------------------------------------------------------
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

        # ---------------------------------------------------------
        # STAGE 4: NIST FIPS 204 ML-DSA-65 Signature Verification
        # ---------------------------------------------------------
        t_s0 = time.perf_counter()
        verified_target = None
        sig_error = None

        if envelope_required:
            if not (credential_id and subject_did and issuer_did and schema_id):
                return {
                    "valid": False,
                    "error_stage": "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION",
                    "error": "Envelope verification required but missing credential metadata (schema_id, credential_id, subject_did, or issuer_did)"
                }
            try:
                m_digest, _ = compute_authenticated_envelope_message(
                    issuer_did=issuer_did,
                    credential_id=str(credential_id),
                    subject_did=subject_did,
                    merkle_root=merkle_root,
                    schema_id=schema_id
                )
            except ValueError as exc:
                return {
                    "valid": False,
                    "error_stage": "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION",
                    "error": f"Malformed envelope metadata: {exc}"
                }
            payload_bytes = m_digest.encode("utf-8")
            if "ECDSA" in resolved_scheme:
                res = ECDSABaselineService.verify(payload_bytes, signature_b64, trusted_pk_b64)
            else:
                res = PQCService.verify(payload_bytes, signature_b64, trusted_pk_b64)

            if res["valid"]:
                verified_target = "AUTHENTICATED_ENVELOPE"
            else:
                sig_error = f"Signature verification failed against Authenticated Credential Envelope: {res.get('error', 'invalid signature')}"
        else:
            candidates = []
            if credential_id and subject_did and issuer_did:
                m_digest, _ = compute_authenticated_envelope_message(
                    issuer_did=issuer_did,
                    credential_id=str(credential_id),
                    subject_did=subject_did,
                    merkle_root=merkle_root,
                    schema_id=schema_id or "urn:xeno:schema:id-credential:v1"
                )
                candidates.append(("AUTHENTICATED_ENVELOPE", m_digest.encode("utf-8")))
            candidates.append(("MERKLE_ROOT", merkle_root.encode("utf-8")))

            for target_name, payload_bytes in candidates:
                if "ECDSA" in resolved_scheme:
                    res = ECDSABaselineService.verify(payload_bytes, signature_b64, trusted_pk_b64)
                else:
                    res = PQCService.verify(payload_bytes, signature_b64, trusted_pk_b64)

                if res["valid"]:
                    verified_target = target_name
                    break
                else:
                    sig_error = res.get("error")

        t_s_ms = (time.perf_counter() - t_s0) * 1000

        if not verified_target:
            return {
                "valid": False,
                "error_stage": "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION",
                "error": sig_error or "Signature verification failed against Merkle root and credential envelope",
                "merkle_verification_time_ms": round(t_m_ms, 3),
                "signature_verification_time_ms": round(t_s_ms, 3)
            }

        total_verification_time_ms = (time.perf_counter() - t0) * 1000

        return {
            "protocol_version": PROTOCOL_VERSION,
            "valid": True,
            "status": "CRYPTOGRAPHICALLY_VERIFIED",
            "verified_target": verified_target,
            "verified_attributes": merkle_res["verified_attributes"],
            "disclosed_count": len(merkle_res["verified_attributes"]),
            "merkle_root": merkle_root,
            "issuer_did": issuer_did,
            "signature_scheme": resolved_scheme,
            "metrics": {
                "merkle_proof_verification_ms": round(t_m_ms, 3),
                "signature_verification_ms": round(t_s_ms, 3),
                "total_workflow_verification_ms": round(total_verification_time_ms, 3)
            }
        }
