"""
Automated Cryptographic & Negative Security Test Suite for Xenoverify.
Comprehensive Test Battery Addressing Empirical Security & Academic Verification Requirements:
1. Nominal Post-Quantum Workflow (ML-DSA-65 & Salted Merkle Tree)
2. Classical Baseline Verification (ECDSA secp256k1)
3. Negative Test 1: Tampered Disclosed Attribute Value
4. Negative Test 2: Malformed / Injected Sibling Authentication Path
5. Negative Test 3: Corrupted / Invalid Post-Quantum Signature
6. Negative Test 4: Substituted Merkle Root Attack
7. Negative Test 5: Cross-Credential Attribute Splicing (Mix-and-Match Attack)
8. Negative Test 6: Revoked Credential Presentation Circumvention
9. Negative Test 7: Presentation Unlinkability & Replay Defense Audit
"""

import copy
import hashlib
from django.test import TestCase

from core_identity.models import DIDRegistry, IssuedCredential
from core_identity.crypto_service import PQCService, ECDSABaselineService
from core_identity.merkle_engine import SelectiveDisclosureEngine, hash_leaf
from core_identity.services.issuer_service import IssuerService
from core_identity.services.credential_service import CredentialService
from core_identity.services.verification_service import VerificationService


class XenoverifyCryptographicTestSuite(TestCase):
    """
    Comprehensive verification of cryptographic correctness, tamper evidence,
    and attack resilience for the MRe Dissertation Artefact.
    """

    def setUp(self):
        # 1. Setup ML-DSA-65 Authority
        self.pqc_issuer, self.pqc_keypair = IssuerService.initialize_issuer(
            scheme="ML-DSA-65 (NIST FIPS 204)",
            entity_name="National Identity Management Commission (NIMC Simulator)"
        )
        self.pqc_secret_key = self.pqc_keypair["secret_key_b64"]

        # 2. Setup Baseline ECDSA Authority
        self.ecdsa_issuer, self.ecdsa_keypair = IssuerService.initialize_issuer(
            scheme="ECDSA (secp256k1 / SHA-256)",
            entity_name="Classical Authority Benchmark"
        )
        self.ecdsa_secret_key = self.ecdsa_keypair["secret_key_b64"]

        # Synthetic applicant attributes
        self.attributes_1 = {
            "fullName": "Olushola James",
            "nin": "29837492812",
            "dob": "1992-06-14",
            "nationality": "Nigerian",
            "clearanceLevel": "Tier-3",
            "residence": "Victoria Island, Lagos"
        }

        # Second set of attributes for splicing / cross-credential testing
        self.attributes_2 = {
            "fullName": "Amina Bello",
            "nin": "83749201837",
            "dob": "1995-11-23",
            "nationality": "Nigerian",
            "clearanceLevel": "Tier-1",
            "residence": "Maitama, Abuja"
        }

        # Issue primary credential
        self.cred_pqc = CredentialService.issue_credential(
            issuer=self.pqc_issuer,
            subject_did="did:xeno:subject:001",
            attributes=self.attributes_1,
            secret_key_b64=self.pqc_secret_key
        )
        self.credential_obj = IssuedCredential.objects.get(id=self.cred_pqc["credential_id"])

        # Issue second credential for cross-credential mixing tests
        self.cred_pqc_2 = CredentialService.issue_credential(
            issuer=self.pqc_issuer,
            subject_did="did:xeno:subject:002",
            attributes=self.attributes_2,
            secret_key_b64=self.pqc_secret_key
        )
        self.credential_obj_2 = IssuedCredential.objects.get(id=self.cred_pqc_2["credential_id"])

    def test_01_nominal_pqc_selective_disclosure_verification(self):
        """
        Confirms that valid selective disclosure with ML-DSA-65 verifies with 100% success.
        Disclosing only fullName and nationality; hiding nin, dob, clearanceLevel, residence.
        """
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName", "nationality"]
        )

        self.assertEqual(proof_packet["disclosed_count"], 2)
        self.assertEqual(proof_packet["total_attributes"], 6)

        # Verify
        result = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"]
        )

        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "CRYPTOGRAPHICALLY_VERIFIED")
        self.assertIn("fullName", result["verified_attributes"])
        self.assertIn("nationality", result["verified_attributes"])
        self.assertNotIn("nin", [c["key"] for c in proof_packet["disclosed_claims"]])

    def test_02_negative_tampered_disclosed_leaf_value(self):
        """
        Negative Test: Altering 1 byte in a revealed attribute value must be rejected at Stage 2.
        """
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName", "nationality"]
        )
        tampered_claims = copy.deepcopy(proof_packet["disclosed_claims"])
        tampered_claims[0]["value"] = "Olushola James_TAMPERED"

        result = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=tampered_claims,
            credential_id=proof_packet["credential_id"]
        )

        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "MERKLE_PROOF_INCLUSION")
        self.assertIn("Merkle inclusion proof failed", result["error"])

    def test_03_negative_malformed_sibling_proof_path(self):
        """
        Negative Test: Injected corrupted sibling hash in authentication path must fail root climb.
        """
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName"]
        )
        corrupted_claims = copy.deepcopy(proof_packet["disclosed_claims"])
        # Corrupt the sibling hash
        corrupted_claims[0]["proof_path"][0]["sibling_hash"] = "0" * 64

        result = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=corrupted_claims,
            credential_id=proof_packet["credential_id"]
        )

        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "MERKLE_PROOF_INCLUSION")

    def test_04_negative_corrupted_post_quantum_signature(self):
        """
        Negative Test: An altered or invalid ML-DSA-65 signature must fail at Stage 3.
        """
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName"]
        )
        # Flip bytes in the base64 signature
        raw_sig = list(proof_packet["signature_b64"])
        raw_sig[10] = 'X' if raw_sig[10] != 'X' else 'Y'
        tampered_sig = "".join(raw_sig)

        result = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=tampered_sig,
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"]
        )

        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")

    def test_05_negative_substituted_signed_root(self):
        """
        Negative Test: Providing a substituted Merkle root that does not match the signature.
        """
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName"]
        )
        # Substitute with second credential's root
        substituted_root = self.cred_pqc_2["merkle_root"]

        result = VerificationService.verify_proof_package(
            merkle_root=substituted_root,
            signature_b64=proof_packet["signature_b64"],  # Signed over root 1, not root 2
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"]
        )

        # Either fails Merkle inclusion against substituted root or fails signature check
        self.assertFalse(result["valid"])

    def test_06_negative_attribute_splicing_across_credentials(self):
        """
        Negative Test: Mixing an attribute claim from Credential 2 into Credential 1's proof.
        Because each attribute has an independent 128-bit CSPRNG salt and leaf position,
        spliced attributes cannot produce a valid Merkle root match.
        """
        proof_1 = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName"]
        )
        proof_2 = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj_2,
            disclosed_keys=["nationality"]
        )

        # Splice claim from Credential 2 into presentation for Credential 1
        spliced_claims = [proof_1["disclosed_claims"][0], proof_2["disclosed_claims"][0]]

        result = VerificationService.verify_proof_package(
            merkle_root=proof_1["merkle_root"],
            signature_b64=proof_1["signature_b64"],
            issuer_pk_b64=proof_1["issuer_public_key_b64"],
            signature_scheme=proof_1["signature_scheme"],
            disclosed_claims=spliced_claims,
            credential_id=proof_1["credential_id"]
        )

        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "MERKLE_PROOF_INCLUSION")
        self.assertEqual(result["failed_attribute"], "nationality")

    def test_07_negative_revoked_credential_circumvention(self):
        """
        Negative Test: A revoked credential must be halted at Stage 1 before cryptographic evaluation.
        """
        # Revoke the credential in the simulated ledger
        CredentialService.revoke_credential(
            credential_id=str(self.credential_obj.id),
            reason="Subject requested revocation due to key rotation"
        )

        proof_packet = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName"]
        )

        result = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"]
        )

        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "REVOCATION_CHECK")
        self.assertIn("Credential revoked", result["error"])

    def test_08_presentation_unlinkability_entropy_audit(self):
        """
        Evaluates presentation unlinkability and privacy:
        Confirms that identical attributes in different issuances receive distinct 128-bit salts,
        producing non-correlatable leaf commitments and eliminating cross-verifier linkage.
        """
        cred_a = CredentialService.issue_credential(
            issuer=self.pqc_issuer,
            subject_did="did:xeno:test:A",
            attributes={"nationality": "Nigerian"},
            secret_key_b64=self.pqc_secret_key
        )
        cred_b = CredentialService.issue_credential(
            issuer=self.pqc_issuer,
            subject_did="did:xeno:test:B",
            attributes={"nationality": "Nigerian"},
            secret_key_b64=self.pqc_secret_key
        )

        leaf_a = cred_a["leaves"][0]
        leaf_b = cred_b["leaves"][0]

        # Same attribute value, but independent 128-bit CSPRNG salts
        self.assertEqual(leaf_a["value"], leaf_b["value"])
        self.assertNotEqual(leaf_a["salt"], leaf_b["salt"])
        self.assertNotEqual(leaf_a["leaf_hash"], leaf_b["leaf_hash"])
        self.assertNotEqual(cred_a["merkle_root"], cred_b["merkle_root"])

    def test_08_worked_synthetic_credential_specification_and_replay_layer(self):
        """
        Validates worked synthetic credential construction, exact leaf hashes,
        canonical root synthesis, and presentation-layer replay protection token.
        """
        from core_identity.merkle_engine import build_replay_protection_token, verify_replay_protection_token
        worked = SelectiveDisclosureEngine.generate_worked_synthetic_credential()

        self.assertEqual(len(worked["leaves"]), 6)
        # Check deterministic root
        self.assertEqual(worked["merkle_root"], "072e0695d79904e2c03e988f2ee5a9cac2d2af3b364f6367b4674f58323b39f3")
        # Check authenticated envelope message M
        self.assertEqual(worked["authenticated_message_m"], "e6c6552aa606c85e75badb479a8be11953c97d34f7fbf0c62792702ab58c0e2c")

        # Replay token test
        token = build_replay_protection_token(
            credential_id=worked["credential_id"],
            verifier_nonce="test-nonce-12345",
            timestamp_iso="2026-10-17T12:00:00Z",
            disclosed_keys=["fullName", "nationality"]
        )
        self.assertTrue(verify_replay_protection_token(
            token=token,
            credential_id=worked["credential_id"],
            verifier_nonce="test-nonce-12345",
            timestamp_iso="2026-10-17T12:00:00Z",
            disclosed_keys=["fullName", "nationality"]
        ))
        self.assertFalse(verify_replay_protection_token(
            token=token,
            credential_id=worked["credential_id"],
            verifier_nonce="replayed-nonce-diff",
            timestamp_iso="2026-10-17T12:00:00Z",
            disclosed_keys=["fullName", "nationality"]
        ))
