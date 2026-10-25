"""
Automated Cryptographic & Negative Security Test Suite for Xenoverify.
Comprehensive Test Battery Addressing Empirical Security & Academic Verification Requirements:
1. Nominal Post-Quantum Workflow (NIST FIPS 204 ML-DSA-65 & Salted Merkle Tree)
2. Negative Test 1: Tampered Disclosed Attribute Value (Stage 2)
3. Negative Test 2: Malformed / Injected Sibling Authentication Path (Stage 2)
4. Negative Test 3: Corrupted / Invalid Post-Quantum Signature (Stage 4)
5. Negative Test 4: Substituted Merkle Root Attack (Stage 3/4)
6. Negative Test 5: Cross-Credential Attribute Splicing (Mix-and-Match Attack, Stage 3)
7. Negative Test 6: Revoked Credential Presentation Circumvention (Stage 1)
8. Presentation Unlinkability & Entropy Audit (CSPRNG Salts)
9. Presentation Replay Protection & Verifier Nonce Verification (Stage 0)
10. Negative Test 7: Untrusted Issuer DID or Substituted Public Key (Stage 2)
11. Authenticated Credential Envelope Verification (Message M Domain Separation)
12. Worked Synthetic Credential Specification & Deterministic Tree Trace
13. Classical Baseline Comparison (ECDSA secp256k1)
"""

import copy
import hashlib
from django.test import TestCase

from core_identity.models import DIDRegistry, IssuedCredential, VerifierNonce
from core_identity.crypto_service import PQCService, ECDSABaselineService
from core_identity.merkle_engine import (
    SelectiveDisclosureEngine,
    hash_leaf,
    compute_authenticated_envelope_message,
    build_replay_protection_token,
    verify_replay_protection_token,
)
from core_identity.services.issuer_service import IssuerService
from core_identity.services.credential_service import CredentialService
from core_identity.services.verification_service import VerificationService


class XenoverifyCryptographicTestSuite(TestCase):
    """
    Comprehensive verification of cryptographic correctness, tamper evidence,
    and attack resilience for the MRe Dissertation Artefact.
    """

    def setUp(self):
        # 1. Setup ML-DSA-65 Authority (NIST FIPS 204)
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
            "fullName": "Alex Carter",
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

        # Issue primary credential (FIPS 204 ML-DSA-65)
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
            issuer_did=proof_packet["issuer_did"],
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
        Negative Test: Altering 1 byte in a revealed attribute value must be rejected at Stage 3.
        """
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName", "nationality"]
        )
        tampered_claims = copy.deepcopy(proof_packet["disclosed_claims"])
        tampered_claims[0]["value"] = "Alex Carter_TAMPERED"

        result = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_did=proof_packet["issuer_did"],
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
            issuer_did=proof_packet["issuer_did"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=corrupted_claims,
            credential_id=proof_packet["credential_id"]
        )

        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "MERKLE_PROOF_INCLUSION")

    def test_04_negative_corrupted_post_quantum_signature(self):
        """
        Negative Test: An altered or invalid ML-DSA-65 signature must fail at Stage 4.
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
            issuer_did=proof_packet["issuer_did"],
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
            issuer_did=proof_packet["issuer_did"],
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
            issuer_did=proof_1["issuer_did"],
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
            issuer_did=proof_packet["issuer_did"],
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

    def test_09_verifier_nonce_replay_protection_defense(self):
        """
        Validates verifier challenge nonce generation, presentation token binding,
        and ensures that replayed presentations are detected and rejected at Stage 0.
        """
        # Step 1: Relying party generates a fresh challenge nonce
        nonce_packet = VerificationService.create_verifier_nonce(validity_seconds=300)
        nonce = nonce_packet["verifier_nonce"]

        # Step 2: Holder extracts proof packet bound to this nonce
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName", "nationality"],
            verifier_nonce=nonce
        )
        self.assertIsNotNone(proof_packet["replay_token"])

        # Step 3: First verification attempt succeeds
        result1 = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_did=proof_packet["issuer_did"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"],
            verifier_nonce=proof_packet["verifier_nonce"],
            timestamp_iso=proof_packet["timestamp_iso"],
            replay_token=proof_packet["replay_token"]
        )
        self.assertTrue(result1["valid"])

        # Step 4: Replay attack: Adversary presents the exact same presentation packet again
        result2 = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_did=proof_packet["issuer_did"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"],
            verifier_nonce=proof_packet["verifier_nonce"],
            timestamp_iso=proof_packet["timestamp_iso"],
            replay_token=proof_packet["replay_token"]
        )
        self.assertFalse(result2["valid"])
        self.assertEqual(result2["error_stage"], "REPLAY_PROTECTION")
        self.assertIn("already consumed", result2["error"])

        # Step 5: Modified challenge nonce mismatch
        result3 = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_did=proof_packet["issuer_did"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"],
            verifier_nonce="forged_nonce_12345",
            timestamp_iso=proof_packet["timestamp_iso"],
            replay_token=proof_packet["replay_token"]
        )
        self.assertFalse(result3["valid"])
        self.assertEqual(result3["error_stage"], "REPLAY_PROTECTION")

    def test_10_negative_unregistered_or_substituted_issuer_key(self):
        """
        Negative Test: Verifier must independently check the Issuer Registry (Stage 2).
        If the presenter supplies an unregistered issuer DID or substitutes their own public key,
        verification must halt at Stage 2.
        """
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName"]
        )

        # Attack A: Presenter provides an unknown / fabricated issuer DID
        res_unknown_did = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_did="did:xeno:unregistered:rogue_authority",
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"],
            require_registry_check=True
        )
        self.assertFalse(res_unknown_did["valid"])
        self.assertEqual(res_unknown_did["error_stage"], "ISSUER_REGISTRY_VERIFICATION")
        self.assertIn("not registered", res_unknown_did["error"])

        # Attack B: Presenter supplies valid issuer DID but substitutes their own public key
        rogue_keypair = PQCService.generate_keypair()
        res_substituted_key = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_did=self.pqc_issuer.did,
            issuer_pk_b64=rogue_keypair["public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"],
            require_registry_check=True
        )
        self.assertFalse(res_substituted_key["valid"])
        self.assertEqual(res_substituted_key["error_stage"], "ISSUER_REGISTRY_VERIFICATION")
        self.assertIn("does not match the anchored public key", res_substituted_key["error"])

    def test_11_authenticated_credential_envelope_verification(self):
        """
        Validates issuance and selective disclosure using domain-separated Authenticated
        Credential Envelope Message M (Section 2.2):
        M = SHA-256( schema_id || ':' || issuer_did || ':' || credential_id || ':' || subject_did || ':' || R )
        """
        cred_envelope = CredentialService.issue_credential(
            issuer=self.pqc_issuer,
            subject_did="did:xeno:subject:envelope_test",
            attributes=self.attributes_1,
            secret_key_b64=self.pqc_secret_key,
            bind_envelope=True
        )
        self.assertEqual(cred_envelope["signed_target"], "AUTHENTICATED_ENVELOPE")
        self.assertIsNotNone(cred_envelope["envelope_message"])
        self.assertEqual(len(cred_envelope["envelope_message"]), 64)

        cred_obj = IssuedCredential.objects.get(id=cred_envelope["credential_id"])
        proof_packet = VerificationService.generate_disclosure_proof(
            credential=cred_obj,
            disclosed_keys=["fullName", "residence"]
        )

        # Successful verification validates envelope message M
        result = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_did=proof_packet["issuer_did"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"],
            subject_did=proof_packet["subject_did"],
            schema_id=proof_packet["schema_id"]
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_target"], "AUTHENTICATED_ENVELOPE")

        # Negative check: tampering subject_did alters envelope message M and fails verification
        tampered_result = VerificationService.verify_proof_package(
            merkle_root=proof_packet["merkle_root"],
            signature_b64=proof_packet["signature_b64"],
            issuer_did=proof_packet["issuer_did"],
            issuer_pk_b64=proof_packet["issuer_public_key_b64"],
            signature_scheme=proof_packet["signature_scheme"],
            disclosed_claims=proof_packet["disclosed_claims"],
            credential_id=proof_packet["credential_id"],
            subject_did="did:xeno:subject:altered_attacker",
            schema_id=proof_packet["schema_id"]
        )
        self.assertFalse(tampered_result["valid"])
        self.assertEqual(tampered_result["error_stage"], "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")

    def test_12_worked_synthetic_credential_specification(self):
        """
        Validates worked synthetic credential construction, exact leaf hashes,
        canonical root synthesis, and authenticated envelope message M.
        Verifies exact match with Section 1 and Section 2 worked example.
        """
        worked = SelectiveDisclosureEngine.generate_worked_synthetic_credential()

        self.assertEqual(len(worked["leaves"]), 6)
        # Deterministic Merkle Root R
        self.assertEqual(worked["merkle_root"], "e44710fed7f939569fd05f05d57401f7f4e50d2696d378370c603ecb8379739c")
        # Deterministic Authenticated Envelope Message M
        self.assertEqual(worked["authenticated_message_m"], "bf243e9f3af4e8f36a56faab77ae5eecf0aa16f57c21f0892e6129f944cfbc01")

    def test_13_classical_ecdsa_baseline_verification(self):
        """
        Validates classical ECDSA secp256k1 baseline issuance and selective disclosure.
        Validates that classical ECDSA signatures are 71 bytes (vs 3,309 bytes for ML-DSA-65).
        """
        cred_ecdsa = CredentialService.issue_credential(
            issuer=self.ecdsa_issuer,
            subject_did="did:xeno:subject:classical_001",
            attributes=self.attributes_1,
            secret_key_b64=self.ecdsa_secret_key
        )
        self.assertIn("ECDSA", cred_ecdsa["signature_scheme"])
        self.assertLessEqual(cred_ecdsa["signature_bytes"], 72)

        cred_obj = IssuedCredential.objects.get(id=cred_ecdsa["credential_id"])
        proof = VerificationService.generate_disclosure_proof(
            credential=cred_obj,
            disclosed_keys=["fullName"]
        )

        result = VerificationService.verify_proof_package(
            merkle_root=proof["merkle_root"],
            signature_b64=proof["signature_b64"],
            issuer_did=proof["issuer_did"],
            issuer_pk_b64=proof["issuer_public_key_b64"],
            signature_scheme=proof["signature_scheme"],
            disclosed_claims=proof["disclosed_claims"],
            credential_id=proof["credential_id"]
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "CRYPTOGRAPHICALLY_VERIFIED")
