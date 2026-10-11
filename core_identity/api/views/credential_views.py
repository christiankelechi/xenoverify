"""
Credential Lifecycle API Views: Issuance, Retrieval, and Revocation.
"""

from rest_framework import status
from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import uuid

from core_identity.api.views.base import BaseAPIView
from core_identity.models import DIDRegistry, IssuedCredential
from core_identity.services import CredentialService, IssuerService
from core_identity.serializers import IssuedCredentialSerializer


class IssueCredentialView(BaseAPIView):
    """
    Issues a synthetic digital credential:
    1. Salts attributes with CSPRNG
    2. Builds Merkle Tree
    3. Signs Merkle Root with ML-DSA-65
    """

    @swagger_auto_schema(
        operation_description="Issue synthetic digital credential with salted Merkle leaf commitments and ML-DSA-65 signature.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["attributes"],
            properties={
                "issuer_did": openapi.Schema(type=openapi.TYPE_STRING, description="Optional DID of the issuer"),
                "subject_did": openapi.Schema(type=openapi.TYPE_STRING, description="Optional DID of the holder"),
                "secret_key_b64": openapi.Schema(type=openapi.TYPE_STRING, description="Private key to sign root"),
                "attributes": openapi.Schema(type=openapi.TYPE_OBJECT, description="Key-value mapping of identity claims")
            }
        ),
        responses={201: "Credential issued successfully with Merkle root and signature"}
    )
    def post(self, request):
        issuer_did = request.data.get("issuer_did")
        subject_did = request.data.get("subject_did", f"did:xeno:holder:{uuid.uuid4().hex[:10]}")
        attributes = request.data.get("attributes")
        secret_key_b64 = request.data.get("secret_key_b64")

        if not attributes or not isinstance(attributes, dict):
            return self.error_response("attributes must be a valid dictionary of key-value pairs")

        if issuer_did:
            issuer = get_object_or_404(DIDRegistry, did=issuer_did)
        else:
            issuer, fallback_sk = IssuerService.get_or_create_default_pqc_issuer()
            if not secret_key_b64:
                secret_key_b64 = fallback_sk

        credential_data = CredentialService.issue_credential(
            issuer=issuer,
            subject_did=subject_did,
            attributes=attributes,
            secret_key_b64=secret_key_b64
        )

        return self.success_response(credential_data, status_code=status.HTTP_201_CREATED)


class ListCredentialsView(BaseAPIView):
    """
    Retrieves credentials for the simulated holder wallet.
    """

    @swagger_auto_schema(
        operation_description="List all issued verifiable credentials stored in the simulated holder wallet.",
        responses={200: IssuedCredentialSerializer(many=True)}
    )
    def get(self, request):
        credentials = IssuedCredential.objects.all().order_by("-issued_at")
        serializer = IssuedCredentialSerializer(credentials, many=True)
        return self.success_response(serializer.data)


class RevokeCredentialView(BaseAPIView):
    """
    Simulated Revocation Ledger: Flags a credential as revoked.
    """

    @swagger_auto_schema(
        operation_description="Revoke a credential on the simulated ledger status accumulator.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["credential_id"],
            properties={
                "credential_id": openapi.Schema(type=openapi.TYPE_STRING),
                "reason": openapi.Schema(type=openapi.TYPE_STRING, default="Suspected compromise")
            }
        ),
        responses={200: "Revocation recorded"}
    )
    def post(self, request):
        credential_id = request.data.get("credential_id")
        reason = request.data.get("reason", "Suspected compromise / holder request")

        if not credential_id:
            return self.error_response("credential_id is required")

        cred = CredentialService.revoke_credential(credential_id, reason)
        return self.success_response({
            "message": f"Credential {credential_id} successfully revoked on simulated ledger.",
            "is_revoked": True,
            "reason": cred.revocation_reason
        })
