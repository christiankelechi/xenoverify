"""
Selective Disclosure Proof Generation & Cryptographic Verifier Views.
Supports 5-Stage Verification Pipeline with Replay Protection, Issuer Registry Check,
and Authenticated Envelope validation.
"""

from rest_framework import status
from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from core_identity.api.views.base import BaseAPIView
from core_identity.models import IssuedCredential
from core_identity.services import VerificationService


class IssueVerifierNonceView(BaseAPIView):
    """
    Issues a fresh, cryptographically secure 128-bit challenge nonce for verifier sessions.
    Used by relying parties to prevent presentation replay attacks.
    """

    @swagger_auto_schema(
        operation_description="Issue fresh 128-bit challenge nonce for presentation replay protection (valid for 300s).",
        responses={200: "Nonce issued"}
    )
    def post(self, request):
        validity = request.data.get("validity_seconds", 300)
        nonce_packet = VerificationService.create_verifier_nonce(validity_seconds=validity)
        return self.success_response(nonce_packet)


class GenerateSelectiveDisclosureProofView(BaseAPIView):
    """
    Holder selectively discloses chosen attributes.
    Extracts Merkle inclusion paths without leaking undisclosed attributes.
    Optionally binds verifier challenge nonce for replay protection.
    """

    @swagger_auto_schema(
        operation_description="Generate Merkle inclusion proofs for selected attributes while withholding private claims.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["credential_id", "disclosed_keys"],
            properties={
                "credential_id": openapi.Schema(type=openapi.TYPE_STRING),
                "disclosed_keys": openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING)),
                "verifier_nonce": openapi.Schema(type=openapi.TYPE_STRING, description="Optional verifier challenge nonce for replay protection")
            }
        ),
        responses={200: "Proof packet generated"}
    )
    def post(self, request):
        credential_id = request.data.get("credential_id")
        disclosed_keys = request.data.get("disclosed_keys", [])
        verifier_nonce = request.data.get("verifier_nonce")

        if not credential_id:
            return self.error_response("credential_id is required")

        cred = get_object_or_404(IssuedCredential, id=credential_id)
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=cred,
            disclosed_keys=disclosed_keys,
            verifier_nonce=verifier_nonce
        )

        return self.success_response(proof_packet)


class VerifySelectiveDisclosureProofView(BaseAPIView):
    """
    Verifier checks:
    Stage 0: Replay Protection & Verifier Nonce Validation
    Stage 1: Revocation Status (Simulated Ledger)
    Stage 2: Independent Issuer Registry Resolution & Public Key Authentication
    Stage 3: Merkle Tree Inclusion Proofs for disclosed claims
    Stage 4: Post-Quantum ML-DSA-65 signature on Authenticated Envelope / Root
    """

    @swagger_auto_schema(
        operation_description="Cryptographically verify ML-DSA-65 signature, Merkle paths, issuer registry anchor, and replay defense.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["merkle_root", "signature_b64", "disclosed_claims"],
            properties={
                "merkle_root": openapi.Schema(type=openapi.TYPE_STRING),
                "signature_b64": openapi.Schema(type=openapi.TYPE_STRING),
                "issuer_did": openapi.Schema(type=openapi.TYPE_STRING, description="Issuer DID in registry"),
                "issuer_public_key_b64": openapi.Schema(type=openapi.TYPE_STRING),
                "signature_scheme": openapi.Schema(type=openapi.TYPE_STRING, default="ML-DSA-65"),
                "credential_id": openapi.Schema(type=openapi.TYPE_STRING),
                "subject_did": openapi.Schema(type=openapi.TYPE_STRING),
                "schema_id": openapi.Schema(type=openapi.TYPE_STRING),
                "verifier_nonce": openapi.Schema(type=openapi.TYPE_STRING),
                "timestamp_iso": openapi.Schema(type=openapi.TYPE_STRING),
                "replay_token": openapi.Schema(type=openapi.TYPE_STRING),
                "disclosed_claims": openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_OBJECT))
            }
        ),
        responses={200: "Verification succeeded", 400: "Verification rejected with cryptographic error"}
    )
    def post(self, request):
        merkle_root = request.data.get("merkle_root")
        signature_b64 = request.data.get("signature_b64")
        issuer_did = request.data.get("issuer_did")
        issuer_pk_b64 = request.data.get("issuer_public_key_b64")
        signature_scheme = request.data.get("signature_scheme", "ML-DSA-65")
        disclosed_claims = request.data.get("disclosed_claims", [])
        credential_id = request.data.get("credential_id")
        subject_did = request.data.get("subject_did")
        schema_id = request.data.get("schema_id", "urn:xeno:schema:id-credential:v1")
        verifier_nonce = request.data.get("verifier_nonce")
        timestamp_iso = request.data.get("timestamp_iso")
        replay_token = request.data.get("replay_token")

        if not merkle_root or not signature_b64:
            return self.error_response("merkle_root and signature_b64 are required")

        result = VerificationService.verify_proof_package(
            merkle_root=merkle_root,
            signature_b64=signature_b64,
            issuer_pk_b64=issuer_pk_b64,
            issuer_did=issuer_did,
            signature_scheme=signature_scheme,
            disclosed_claims=disclosed_claims,
            credential_id=credential_id,
            subject_did=subject_did,
            schema_id=schema_id,
            verifier_nonce=verifier_nonce,
            timestamp_iso=timestamp_iso,
            replay_token=replay_token,
            require_registry_check=True
        )

        if not result["valid"]:
            return self.error_response(
                message=result.get("error", "Cryptographic verification failed"),
                status_code=status.HTTP_400_BAD_REQUEST,
                extra=result
            )

        return self.success_response(result)
