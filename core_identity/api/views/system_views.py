"""
System Info & Academic Specification API Views.
"""

from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from core_identity.api.views.base import BaseAPIView


class SystemInfoView(BaseAPIView):
    """
    Returns exact theoretical and implementation parameters demanded by MRe Chapter 3.
    """

    @swagger_auto_schema(
        operation_description="Retrieve system architectural scope, cryptographic parameters, and DSRM Table 3.1 mapping.",
        responses={200: "System specifications and standard mappings"}
    )
    def get(self, request):
        return self.success_response({
            "project": "Xenoverify Post-Quantum Identity Prototype",
            "degree": "MRe (Master of Research)",
            "dsrm_framework": {
                "methodology": "Design Science Research Methodology (Peffers et al., 2007)",
                "scope_table": {
                    "Post-quantum signing": "Implemented (ML-DSA-65 NIST FIPS 204)",
                    "Selective disclosure": "Implemented (Salted Merkle Tree Inclusion Proofs)",
                    "Core verification workflow": "Implemented (Integrated Verification Engine)",
                    "Wallet": "Simulated (In-browser Holder State Management)",
                    "Ledger/blockchain": "Simulated (Cryptographic DID Registry)",
                    "Revocation": "Simulated (Cryptographic Status Accumulator)"
                }
            },
            "cryptographic_parameters": {
                "scheme": "ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm)",
                "standard": "NIST FIPS 204 (Finalized August 2024)",
                "nist_security_category": 3,
                "public_key_size_bytes": 1952,
                "private_key_size_bytes": 4032,
                "signature_size_bytes": 3309,
                "hash_function": "SHA-256 for leaf commitments and Merkle nodes",
                "salt_entropy": "128-bit CSPRNG secrets.token_hex(16)"
            },
            "classical_comparison": {
                "scheme": "ECDSA over secp256k1",
                "public_key_size_bytes": 88,
                "signature_size_bytes": 71,
                "quantum_vulnerability": "Breakable by polynomial-time Shor's algorithm"
            }
        })
