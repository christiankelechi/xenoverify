"""
Issuer Authority Controller Endpoints.
"""

from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from core_identity.api.views.base import BaseAPIView
from core_identity.services import IssuerService
from core_identity.serializers import DIDRegistrySerializer


class InitializeIssuerView(BaseAPIView):
    """
    Initializes a simulated Issuer authority (e.g., NIMC) with ML-DSA-65 or ECDSA keypair.
    """

    @swagger_auto_schema(
        operation_description="Initialize a new Post-Quantum Issuer DID and generate ML-DSA-65 keypair.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "scheme": openapi.Schema(type=openapi.TYPE_STRING, default="ML-DSA-65"),
                "entity_name": openapi.Schema(type=openapi.TYPE_STRING, default="National Identity Authority (NIMC Simulator)")
            }
        ),
        responses={200: "Issuer created successfully with public and private keys"}
    )
    def post(self, request):
        scheme = request.data.get("scheme", "ML-DSA-65")
        entity_name = request.data.get("entity_name", "National Identity Authority (NIMC Simulator)")

        issuer, keypair = IssuerService.initialize_issuer(scheme=scheme, entity_name=entity_name)

        return self.success_response({
            "message": "Issuer authority initialized successfully",
            "issuer": DIDRegistrySerializer(issuer).data,
            "secret_key_b64": keypair["secret_key_b64"],
            "keygen_time_ms": keypair["keygen_time_ms"]
        })
