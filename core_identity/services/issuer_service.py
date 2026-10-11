"""
Service Layer for Issuer Authority Management.
Adheres to Single Responsibility Principle (SRP) and Domain-Driven design.
"""

import uuid
from typing import Dict, Any, Tuple
from django.db import transaction

from core_identity.models import DIDRegistry
from core_identity.crypto_service import PQCService, ECDSABaselineService


class IssuerService:
    """
    Handles lifecycle operations for Decentralized Identifier (DID) Authorities.
    """

    @classmethod
    @transaction.atomic
    def initialize_issuer(cls, scheme: str = "ML-DSA-65", entity_name: str = "National Identity Authority (NIMC Simulator)") -> Tuple[DIDRegistry, Dict[str, Any]]:
        """
        Creates an Issuer DID anchored to either Post-Quantum (ML-DSA-65) or Classical (ECDSA) public keys.
        """
        did_str = f"did:xeno:issuer:{uuid.uuid4().hex[:12]}"

        if "ECDSA" in scheme:
            keypair = ECDSABaselineService.generate_keypair()
        else:
            keypair = PQCService.generate_keypair()

        issuer = DIDRegistry.objects.create(
            did=did_str,
            entity_name=entity_name,
            scheme=scheme,
            public_key_b64=keypair["public_key_b64"],
            public_key_bytes=keypair["public_key_bytes"],
            is_active=True
        )

        return issuer, keypair

    @classmethod
    def get_or_create_default_pqc_issuer(cls) -> Tuple[DIDRegistry, str]:
        """
        Ensures a default ML-DSA-65 root issuer is always present in the simulated registry.
        """
        issuer = DIDRegistry.objects.filter(scheme__icontains="ML-DSA").first()
        if issuer:
            # For demonstration in prototype if secret key is not provided by client
            return issuer, ""

        keypair = PQCService.generate_keypair()
        issuer = DIDRegistry.objects.create(
            did="did:xeno:nimc:root",
            entity_name="Federal Ministry of Digital Identity (NIMC PQC Root)",
            scheme="ML-DSA-65",
            public_key_b64=keypair["public_key_b64"],
            public_key_bytes=keypair["public_key_bytes"]
        )
        return issuer, keypair["secret_key_b64"]
