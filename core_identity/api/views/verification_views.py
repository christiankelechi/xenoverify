"""
Selective Disclosure Proof Generation & Cryptographic Verifier Views.
"""

from rest_framework import status
from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from core_identity.api.views.base import BaseAPIView
from core_identity.models import IssuedCredential
from core_identity.services import VerificationService


class GenerateSelectiveDisclosureProofView(BaseAPIView):
    """
    Holder selectively discloses chosen attributes.
    Extracts Merkle inclusion paths without leaking undisclosed attributes.
    """

    @swagger_auto_schema(
        operation_description="Generate Merkle inclusion proofs for selected attributes while withholding private claims.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["credential_id", "disclosed_keys"],
            properties={
                "credential_id": openapi.Schema(type=openapi.TYPE_STRING),
                "disclosed_keys": openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING))
            }
        ),
        responses={200: "Proof packet generated"}
    )
    def post(self, request):
        credential_id = request.data.get("credential_id")
        disclosed_keys = request.data.get("disclosed_keys", [])

        if not credential_id:
            return self.error_response("credential_id is required")

        cred = get_object_or_404(IssuedCredential, id=credential_id)
        proof_packet = VerificationService.generate_disclosure_proof(cred, disclosed_keys)

        return self.success_response(proof_packet)


class VerifySelectiveDisclosureProofView(BaseAPIView):
    """
    Verifier checks:
    1. Revocation Status (Simulated Ledger)
    2. Merkle Tree Inclusion Proofs for disclosed claims
    3. Post-Quantum ML-DSA-65 signature on the Merkle root
    4. Tamper detection (Negative tests)
    """

    @swagger_auto_schema(
        operation_description="Cryptographically verify ML-DSA-65 signature and Merkle inclusion paths.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["merkle_root", "signature_b64", "issuer_public_key_b64", "disclosed_claims"],
            properties={
                "merkle_root": openapi.Schema(type=openapi.TYPE_STRING),
                "signature_b64": openapi.Schema(type=openapi.TYPE_STRING),
                "issuer_public_key_b64": openapi.Schema(type=openapi.TYPE_STRING),
                "signature_scheme": openapi.Schema(type=openapi.TYPE_STRING, default="ML-DSA-65"),
                "credential_id": openapi.Schema(type=openapi.TYPE_STRING),
                "disclosed_claims": openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_OBJECT))
            }
        ),
        responses={200: "Verification succeeded", 400: "Verification rejected with cryptographic error"}
    )
    def post(self, request):
        merkle_root = request.data.get("merkle_root")
        signature_b64 = request.data.get("signature_b64")
        issuer_pk_b64 = request.data.get("issuer_public_key_b64")
        signature_scheme = request.data.get("signature_scheme", "ML-DSA-65")
        disclosed_claims = request.data.get("disclosed_claims", [])
        credential_id = request.data.get("credential_id")

        if not merkle_root or not signature_b64 or not issuer_pk_b64:
            return self.error_response("merkle_root, signature_b64, and issuer_public_key_b64 are required")

        result = VerificationService.verify_proof_package(
            merkle_root=merkle_root,
            signature_b64=signature_b64,
            issuer_pk_b64=issuer_pk_b64,
            signature_scheme=signature_scheme,
            disclosed_claims=disclosed_claims,
            credential_id=credential_id
        )

        if not result["valid"]:
            return self.error_response(
                message=result.get("error", "Cryptographic verification failed"),
                status_code=status.HTTP_400_BAD_REQUEST,
                extra=result
            )

        return self.success_response(result)
