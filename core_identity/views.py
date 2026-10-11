"""
REST API Views and Controller Logic for Xenoverify.
Endpoints:
1. /api/system/info/        -> Returns system specs, NIST FIPS 204 parameters, DSRM Table 3.1 mapping
2. /api/issuers/initialize/ -> Creates or fetches default Post-Quantum Issuer DID & Keypair
3. /api/credentials/issue/  -> Issues credential, salts leaves, generates Merkle root, signs with ML-DSA-65
4. /api/credentials/list/   -> Lists all issued credentials (for simulated holder wallet)
5. /api/proofs/generate/    -> Generates selective disclosure packet with Merkle paths for selected keys
6. /api/proofs/verify/      -> Cryptographic verifier checking ML-DSA-65 signature + Merkle inclusion paths
7. /api/credentials/revoke/ -> Simulates credential revocation
8. /api/benchmarks/run/     -> Automated comparative benchmark suite: ML-DSA-65 vs Classical ECDSA
"""

import time
import uuid
import statistics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404

from .models import DIDRegistry, IssuedCredential, EvaluationLog
from .serializers import DIDRegistrySerializer, IssuedCredentialSerializer, EvaluationLogSerializer
from .crypto_service import PQCService, ECDSABaselineService
from .merkle_engine import SelectiveDisclosureEngine


class SystemInfoView(APIView):
    """
    Returns exact theoretical and implementation parameters demanded by the supervisor.
    """
    def get(self, request):
        return Response({
            "project": "Xenoverify Post-Quantum Identity Prototype",
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
                "signature_size_bytes": 3293,
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


class InitializeIssuerView(APIView):
    """
    Initializes the simulated Issuer authority with ML-DSA-65 keypair.
    """
    def post(self, request):
        scheme = request.data.get("scheme", "ML-DSA-65")
        entity_name = request.data.get("entity_name", "National Identity Authority (NIMC Simulator)")

        # Create new Issuer DID
        did_str = f"did:xeno:issuer:{uuid.uuid4().hex[:12]}"
        
        if scheme == "ML-DSA-65":
            keys = PQCService.generate_keypair()
        else:
            keys = ECDSABaselineService.generate_keypair()

        # Cache private key in session or mock storage for signing
        issuer = DIDRegistry.objects.create(
            did=did_str,
            entity_name=entity_name,
            scheme=scheme,
            public_key_b64=keys["public_key_b64"],
            public_key_bytes=keys["public_key_bytes"],
        )

        return Response({
            "message": "Issuer authority initialized successfully",
            "issuer": DIDRegistrySerializer(issuer).data,
            "secret_key_b64": keys["secret_key_b64"],
            "keygen_time_ms": keys["keygen_time_ms"]
        })


class IssueCredentialView(APIView):
    """
    Issues a synthetic digital credential:
    1. Salts each attribute
    2. Builds Merkle Tree
    3. Signs Merkle Root with ML-DSA-65 (or ECDSA)
    """
    def post(self, request):
        issuer_did = request.data.get("issuer_did")
        subject_did = request.data.get("subject_did", f"did:xeno:holder:{uuid.uuid4().hex[:10]}")
        attributes = request.data.get("attributes")
        secret_key_b64 = request.data.get("secret_key_b64")

        if not attributes or not isinstance(attributes, dict):
            return Response({"error": "attributes must be a valid dictionary of key-value pairs"}, status=status.HTTP_400_BAD_REQUEST)

        # Get or create default issuer if not passed
        if issuer_did:
            issuer = get_object_or_404(DIDRegistry, did=issuer_did)
        else:
            issuer = DIDRegistry.objects.filter(scheme__icontains="ML-DSA").first()
            if not issuer:
                keys = PQCService.generate_keypair()
                issuer = DIDRegistry.objects.create(
                    did=f"did:xeno:nimc:root",
                    entity_name="Federal Ministry of Digital Identity (NIMC PQC Root)",
                    scheme="ML-DSA-65",
                    public_key_b64=keys["public_key_b64"],
                    public_key_bytes=keys["public_key_bytes"]
                )
                secret_key_b64 = keys["secret_key_b64"]

        # Step 1: Create Merkle Commitment
        commitment = SelectiveDisclosureEngine.create_credential_commitment(attributes)
        merkle_root = commitment["merkle_root"]

        # Step 2: Sign Root with ML-DSA-65
        t0 = time.perf_counter()
        if "ECDSA" in issuer.scheme:
            sig_res = ECDSABaselineService.sign(merkle_root.encode("utf-8"), secret_key_b64)
        else:
            sig_res = PQCService.sign(merkle_root.encode("utf-8"), secret_key_b64)
        total_issuance_time_ms = (time.perf_counter() - t0) * 1000

        # Step 3: Persist Credential
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

        return Response({
            "credential_id": str(cred.id),
            "subject_did": subject_did,
            "issuer_did": issuer.did,
            "merkle_root": merkle_root,
            "signature_scheme": issuer.scheme,
            "signature_b64": sig_res["signature_b64"],
            "signature_bytes": sig_res["signature_bytes"],
            "issuance_time_ms": round(total_issuance_time_ms, 3),
            "leaves": commitment["leaves"],
            "attributes": attributes
        }, status=status.HTTP_201_CREATED)


class ListCredentialsView(APIView):
    """
    List credentials for simulated wallet holder.
    """
    def get(self, request):
        credentials = IssuedCredential.objects.all().order_by("-issued_at")
        serializer = IssuedCredentialSerializer(credentials, many=True)
        return Response(serializer.data)


class GenerateSelectiveDisclosureProofView(APIView):
    """
    Holder selectively discloses chosen attributes (e.g. nationality & age only).
    Produces cryptographic packet with Merkle inclusion paths without revealing withheld leaves.
    """
    def post(self, request):
        credential_id = request.data.get("credential_id")
        disclosed_keys = request.data.get("disclosed_keys", [])

        cred = get_object_or_404(IssuedCredential, id=credential_id)

        t0 = time.perf_counter()
        proof_packet = SelectiveDisclosureEngine.generate_disclosure_proof(
            all_leaves=cred.leaves_json,
            disclosed_keys=disclosed_keys
        )
        generation_time_ms = (time.perf_counter() - t0) * 1000

        response_packet = {
            "credential_id": str(cred.id),
            "issuer_did": cred.issuer.did,
            "issuer_public_key_b64": cred.issuer.public_key_b64,
            "merkle_root": cred.merkle_root,
            "signature_scheme": cred.signature_scheme,
            "signature_b64": cred.signature_b64,
            "signature_bytes": cred.signature_bytes,
            "disclosed_claims": proof_packet["disclosed_claims"],
            "disclosed_count": proof_packet["disclosed_count"],
            "total_attributes": proof_packet["total_attributes"],
            "proof_generation_time_ms": round(generation_time_ms, 3)
        }

        return Response(response_packet)


class VerifySelectiveDisclosureProofView(APIView):
    """
    Verifier checks:
    1. Revocation Status (Simulated Ledger)
    2. Merkle Tree Inclusion Proofs for disclosed attributes
    3. Quantum-resistant ML-DSA-65 signature on the Merkle root
    4. Tamper detection (Negative testing)
    """
    def post(self, request):
        t0 = time.perf_counter()
        issuer_did = request.data.get("issuer_did")
        issuer_pk_b64 = request.data.get("issuer_public_key_b64")
        merkle_root = request.data.get("merkle_root")
        signature_b64 = request.data.get("signature_b64")
        signature_scheme = request.data.get("signature_scheme", "ML-DSA-65")
        disclosed_claims = request.data.get("disclosed_claims", [])
        credential_id = request.data.get("credential_id")

        # 1. Check Revocation (Simulated Ledger)
        if credential_id:
            try:
                cred = IssuedCredential.objects.get(id=credential_id)
                if cred.is_revoked:
                    return Response({
                        "valid": False,
                        "error_stage": "REVOCATION_CHECK",
                        "error": f"Credential has been revoked: {cred.revocation_reason or 'No reason specified'}"
                    }, status=status.HTTP_400_BAD_REQUEST)
            except IssuedCredential.DoesNotExist:
                pass

        # 2. Verify Merkle Selective Disclosure Inclusion Proof
        t_merkle_0 = time.perf_counter()
        merkle_res = SelectiveDisclosureEngine.verify_disclosure_proof(merkle_root, disclosed_claims)
        t_merkle_ms = (time.perf_counter() - t_merkle_0) * 1000

        if not merkle_res["valid"]:
            return Response({
                "valid": False,
                "error_stage": "MERKLE_PROOF_INCLUSION",
                "error": merkle_res.get("error"),
                "failed_attribute": merkle_res.get("failed_attribute"),
                "merkle_verification_time_ms": round(t_merkle_ms, 3)
            }, status=status.HTTP_400_BAD_REQUEST)

        # 3. Verify Signature on Merkle Root
        t_sig_0 = time.perf_counter()
        if "ECDSA" in signature_scheme:
            sig_res = ECDSABaselineService.verify(merkle_root.encode("utf-8"), signature_b64, issuer_pk_b64)
        else:
            sig_res = PQCService.verify(merkle_root.encode("utf-8"), signature_b64, issuer_pk_b64)
        t_sig_ms = (time.perf_counter() - t_sig_0) * 1000

        if not sig_res["valid"]:
            return Response({
                "valid": False,
                "error_stage": "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION",
                "error": sig_res.get("error", "Signature verification failed"),
                "merkle_verification_time_ms": round(t_merkle_ms, 3),
                "signature_verification_time_ms": round(t_sig_ms, 3)
            }, status=status.HTTP_400_BAD_REQUEST)

        total_verification_time_ms = (time.perf_counter() - t0) * 1000

        return Response({
            "valid": True,
            "status": "CRYPTOGRAPHICALLY_VERIFIED",
            "verified_attributes": merkle_res["verified_attributes"],
            "disclosed_count": len(merkle_res["verified_attributes"]),
            "merkle_root": merkle_root,
            "signature_scheme": signature_scheme,
            "metrics": {
                "merkle_proof_verification_ms": round(t_merkle_ms, 3),
                "signature_verification_ms": round(t_sig_ms, 3),
                "total_workflow_verification_ms": round(total_verification_time_ms, 3)
            }
        })


class RevokeCredentialView(APIView):
    """
    Simulated Revocation Ledger: Flags credential as revoked.
    """
    def post(self, request):
        credential_id = request.data.get("credential_id")
        reason = request.data.get("reason", "Suspected compromise / holder request")
        cred = get_object_or_404(IssuedCredential, id=credential_id)
        cred.is_revoked = True
        cred.revocation_reason = reason
        cred.save()
        return Response({
            "message": f"Credential {credential_id} successfully revoked on simulated ledger.",
            "is_revoked": True,
            "reason": reason
        })


class RunBenchmarkSuiteView(APIView):
    """
    Automated Chapter 4 Experimental Suite:
    Executes N iterations across ML-DSA-65 vs Classical ECDSA,
    calculates Mean, Median, p95 tail latencies, signature bytes, and proof overhead.
    """
    def post(self, request):
        iterations = int(request.data.get("iterations", 20))
        iterations = max(5, min(iterations, 100))  # Cap between 5 and 100 for fast response

        sample_attrs = {
            "fullName": "Olushola James",
            "nin": "28374928192",
            "dob": "1993-08-20",
            "nationality": "Nigerian",
            "stateOfOrigin": "Ondo",
            "bvn": "22938472819",
            "clearanceLevel": "Tier-3",
            "address": "Victoria Island, Lagos"
        }

        # 1. Run ML-DSA-65 Benchmark
        pqc_keygen_times, pqc_sign_times, pqc_verify_times = [], [], []
        pqc_keys = PQCService.generate_keypair()
        commitment = SelectiveDisclosureEngine.create_credential_commitment(sample_attrs)
        root = commitment["merkle_root"]
        disclosure = SelectiveDisclosureEngine.generate_disclosure_proof(commitment["leaves"], ["fullName", "nationality", "clearanceLevel"])

        for _ in range(iterations):
            # Keygen
            kg = PQCService.generate_keypair()
            pqc_keygen_times.append(kg["keygen_time_ms"])
            # Sign
            s = PQCService.sign(root.encode("utf-8"), pqc_keys["secret_key_b64"])
            pqc_sign_times.append(s["sign_time_ms"])
            # Verify
            v = PQCService.verify(root.encode("utf-8"), s["signature_b64"], pqc_keys["public_key_b64"])
            pqc_verify_times.append(v["verify_time_ms"])

        # 2. Run Classical ECDSA Benchmark
        ecdsa_keygen_times, ecdsa_sign_times, ecdsa_verify_times = [], [], []
        ecdsa_keys = ECDSABaselineService.generate_keypair()

        for _ in range(iterations):
            kg = ECDSABaselineService.generate_keypair()
            ecdsa_keygen_times.append(kg["keygen_time_ms"])
            s = ECDSABaselineService.sign(root.encode("utf-8"), ecdsa_keys["secret_key_b64"])
            ecdsa_sign_times.append(s["sign_time_ms"])
            v = ECDSABaselineService.verify(root.encode("utf-8"), s["signature_b64"], ecdsa_keys["public_key_b64"])
            ecdsa_verify_times.append(v["verify_time_ms"])

        def calc_stats(lst):
            s_lst = sorted(lst)
            p95_idx = int(0.95 * len(s_lst))
            return {
                "mean_ms": round(statistics.mean(lst), 3),
                "median_ms": round(statistics.median(lst), 3),
                "p95_ms": round(s_lst[min(p95_idx, len(s_lst) - 1)], 3),
                "min_ms": round(min(lst), 3),
                "max_ms": round(max(lst), 3)
            }

        benchmark_results = {
            "iterations": iterations,
            "attribute_count": len(sample_attrs),
            "disclosed_attribute_count": len(disclosure["disclosed_claims"]),
            "ml_dsa_65": {
                "scheme": "ML-DSA-65 (NIST FIPS 204)",
                "public_key_bytes": pqc_keys["public_key_bytes"],
                "signature_bytes": 3293,
                "keygen": calc_stats(pqc_keygen_times),
                "sign": calc_stats(pqc_sign_times),
                "verify": calc_stats(pqc_verify_times)
            },
            "ecdsa_baseline": {
                "scheme": "ECDSA (secp256k1)",
                "public_key_bytes": ecdsa_keys["public_key_bytes"],
                "signature_bytes": 71,
                "keygen": calc_stats(ecdsa_keygen_times),
                "sign": calc_stats(ecdsa_sign_times),
                "verify": calc_stats(ecdsa_verify_times)
            },
            "selective_disclosure_merkle": {
                "algorithm": "SHA-256 + 128-bit Salt per leaf",
                "leaves_count": len(sample_attrs),
                "disclosed_count": 3,
                "leaf_hash_size_bytes": 32,
                "merkle_root_hex": root
            }
        }

        return Response(benchmark_results)
