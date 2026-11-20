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
import json
from datetime import timedelta
from django.utils import timezone
from django.test import TestCase
from rest_framework.test import APIClient

from core_identity.models import DIDRegistry, IssuedCredential, VerifierNonce
from core_identity.crypto_service import PQCService, ECDSABaselineService
from core_identity.merkle_engine import (
    SelectiveDisclosureEngine,
    hash_leaf,
    canonical_attribute_encoding,
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

    def _fresh_proof(self, credential_obj, disclosed_keys):
        """Helper: obtains a fresh single-use verifier nonce and extracts bound proof packet."""
        nonce = VerificationService.create_verifier_nonce(validity_seconds=300)["verifier_nonce"]
        return VerificationService.generate_disclosure_proof(
            credential=credential_obj,
            disclosed_keys=disclosed_keys,
            verifier_nonce=nonce,
        )

    def _verify_packet(self, packet, **overrides):
        """Helper: submits proof packet to default fail-closed verify_proof_package."""
        kwargs = dict(
            merkle_root=packet["merkle_root"],
            signature_b64=packet["signature_b64"],
            issuer_did=packet["issuer_did"],
            issuer_pk_b64=packet.get("issuer_public_key_b64"),
            signature_scheme=packet["signature_scheme"],
            disclosed_claims=packet["disclosed_claims"],
            credential_id=packet["credential_id"],
            subject_did=packet["subject_did"],
            schema_id=packet["schema_id"],
            verifier_nonce=packet.get("verifier_nonce"),
            timestamp_iso=packet.get("timestamp_iso"),
            replay_token=packet.get("replay_token"),
        )
        kwargs.update(overrides)
        return VerificationService.verify_proof_package(**kwargs)

    def test_01_nominal_pqc_selective_disclosure_verification(self):
        """
        Confirms that valid selective disclosure with ML-DSA-65 verifies with 100% success
        under strict fail-closed defaults (nonce + token + registry + envelope).
        """
        proof_packet = self._fresh_proof(self.credential_obj, ["fullName", "nationality"])
        self.assertEqual(proof_packet["disclosed_count"], 2)
        self.assertEqual(proof_packet["total_attributes"], 6)

        result = self._verify_packet(proof_packet)
        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "CRYPTOGRAPHICALLY_VERIFIED")
        self.assertEqual(result["verified_target"], "AUTHENTICATED_ENVELOPE")
        self.assertIn("fullName", result["verified_attributes"])
        self.assertIn("nationality", result["verified_attributes"])
        self.assertNotIn("nin", [c["key"] for c in proof_packet["disclosed_claims"]])

    def test_02_negative_tampered_disclosed_leaf_value(self):
        """
        Negative Test: Altering 1 byte in a revealed attribute value must be rejected at Stage 3.
        """
        proof_packet = self._fresh_proof(self.credential_obj, ["fullName", "nationality"])
        tampered_claims = copy.deepcopy(proof_packet["disclosed_claims"])
        tampered_claims[0]["value"] = "Alex Carter_TAMPERED"

        result = self._verify_packet(proof_packet, disclosed_claims=tampered_claims)
        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "MERKLE_PROOF_INCLUSION")
        self.assertIn("Merkle inclusion proof failed", result["error"])

    def test_03_negative_malformed_sibling_proof_path(self):
        """
        Negative Test: Injected corrupted sibling hash in authentication path must fail root climb.
        """
        proof_packet = self._fresh_proof(self.credential_obj, ["fullName"])
        corrupted_claims = copy.deepcopy(proof_packet["disclosed_claims"])
        corrupted_claims[0]["proof_path"][0]["sibling_hash"] = "0" * 64

        result = self._verify_packet(proof_packet, disclosed_claims=corrupted_claims)
        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "MERKLE_PROOF_INCLUSION")

    def test_04_negative_corrupted_post_quantum_signature(self):
        """
        Negative Test: An altered or invalid ML-DSA-65 signature must fail at Stage 4.
        """
        proof_packet = self._fresh_proof(self.credential_obj, ["fullName"])
        raw_sig = list(proof_packet["signature_b64"])
        raw_sig[10] = 'X' if raw_sig[10] != 'X' else 'Y'
        tampered_sig = "".join(raw_sig)

        result = self._verify_packet(proof_packet, signature_b64=tampered_sig)
        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")

    def test_05_negative_substituted_signed_root(self):
        """
        Negative Test: Providing a substituted Merkle root that does not match the signature.
        """
        proof_packet = self._fresh_proof(self.credential_obj, ["fullName"])
        substituted_root = self.cred_pqc_2["merkle_root"]

        result = self._verify_packet(proof_packet, merkle_root=substituted_root)
        self.assertFalse(result["valid"])

    def test_06_negative_attribute_splicing_across_credentials(self):
        """
        Negative Test: Mixing an attribute claim from Credential 2 into Credential 1's proof.
        """
        proof_1 = self._fresh_proof(self.credential_obj, ["fullName"])
        proof_2 = self._fresh_proof(self.credential_obj_2, ["nationality"])
        spliced_claims = [proof_1["disclosed_claims"][0], proof_2["disclosed_claims"][0]]
        # Match replay_token to the spliced keys so Stage 0 lets execution reach Stage 3 Merkle check
        spliced_tok = build_replay_protection_token(
            proof_1["credential_id"], proof_1["verifier_nonce"], proof_1["timestamp_iso"], ["fullName", "nationality"]
        )

        result = self._verify_packet(proof_1, disclosed_claims=spliced_claims, replay_token=spliced_tok)
        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "MERKLE_PROOF_INCLUSION")
        self.assertEqual(result["failed_attribute"], "nationality")

    def test_07_negative_revoked_credential_circumvention(self):
        """
        Negative Test: A revoked credential must be halted at Stage 1 before cryptographic evaluation.
        """
        CredentialService.revoke_credential(
            credential_id=str(self.credential_obj.id),
            reason="Subject requested revocation due to key rotation"
        )
        proof_packet = self._fresh_proof(self.credential_obj, ["fullName"])
        result = self._verify_packet(proof_packet)

        self.assertFalse(result["valid"])
        self.assertEqual(result["error_stage"], "REVOCATION_CHECK")
        self.assertIn("Credential revoked", result["error"])

    def test_08_presentation_unlinkability_entropy_audit(self):
        """
        Evaluates independent-issuance salt entropy (distinct commitments across issuances),
        and confirms repeated presentations of one credential share the same Merkle root.
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

        self.assertEqual(leaf_a["value"], leaf_b["value"])
        self.assertNotEqual(leaf_a["salt"], leaf_b["salt"])
        self.assertNotEqual(leaf_a["leaf_hash"], leaf_b["leaf_hash"])
        self.assertNotEqual(cred_a["merkle_root"], cred_b["merkle_root"])

        # Repeated presentations from one credential expose the same static root
        pres_1 = VerificationService.generate_disclosure_proof(self.credential_obj, ["fullName"])
        pres_2 = VerificationService.generate_disclosure_proof(self.credential_obj, ["nationality"])
        self.assertEqual(pres_1["merkle_root"], pres_2["merkle_root"])

    def test_09_verifier_nonce_replay_protection_defense(self):
        """
        Validates verifier challenge nonce generation, presentation token binding,
        and ensures that replayed presentations are detected and rejected at Stage 0.
        """
        proof_packet = self._fresh_proof(self.credential_obj, ["fullName", "nationality"])
        self.assertIsNotNone(proof_packet["replay_token"])

        result1 = self._verify_packet(proof_packet)
        self.assertTrue(result1["valid"])

        result2 = self._verify_packet(proof_packet)
        self.assertFalse(result2["valid"])
        self.assertEqual(result2["error_stage"], "REPLAY_PROTECTION")
        self.assertIn("already consumed", result2["error"])

        result3 = self._verify_packet(proof_packet, verifier_nonce="forged_nonce_12345")
        self.assertFalse(result3["valid"])
        self.assertEqual(result3["error_stage"], "REPLAY_PROTECTION")

    def test_10_negative_unregistered_or_substituted_issuer_key(self):
        """
        Negative Test: Verifier must independently check the Issuer Registry (Stage 2).
        """
        proof_unknown = self._fresh_proof(self.credential_obj, ["fullName"])
        res_unknown_did = self._verify_packet(
            proof_unknown,
            issuer_did="did:xeno:unregistered:rogue_authority",
        )
        self.assertFalse(res_unknown_did["valid"])
        self.assertEqual(res_unknown_did["error_stage"], "ISSUER_REGISTRY_VERIFICATION")
        self.assertIn("not registered", res_unknown_did["error"])

        proof_sub = self._fresh_proof(self.credential_obj, ["fullName"])
        rogue_keypair = PQCService.generate_keypair()
        res_substituted_key = self._verify_packet(
            proof_sub,
            issuer_pk_b64=rogue_keypair["public_key_b64"],
        )
        self.assertFalse(res_substituted_key["valid"])
        self.assertEqual(res_substituted_key["error_stage"], "ISSUER_REGISTRY_VERIFICATION")
        self.assertIn("does not match the anchored public key", res_substituted_key["error"])

    def test_11_authenticated_credential_envelope_verification(self):
        """
        Validates issuance and selective disclosure using domain-separated Authenticated
        Credential Envelope Message M under Protocol xeno-merkle-mldsa-v2.
        """
        cred_envelope = CredentialService.issue_credential(
            issuer=self.pqc_issuer,
            subject_did="did:xeno:subject:envelope_test",
            attributes=self.attributes_1,
            secret_key_b64=self.pqc_secret_key,
            bind_envelope=True
        )
        self.assertEqual(cred_envelope["signed_target"], "AUTHENTICATED_ENVELOPE")
        self.assertEqual(len(cred_envelope["envelope_message"]), 64)

        cred_obj = IssuedCredential.objects.get(id=cred_envelope["credential_id"])
        proof_valid = self._fresh_proof(cred_obj, ["fullName", "residence"])
        result = self._verify_packet(proof_valid)
        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_target"], "AUTHENTICATED_ENVELOPE")

        # Tampering subject_did must fail Stage 4 envelope signature check
        proof_tamper = self._fresh_proof(cred_obj, ["fullName", "residence"])
        tampered_result = self._verify_packet(proof_tamper, subject_did="did:xeno:subject:altered_attacker")
        self.assertFalse(tampered_result["valid"])
        self.assertEqual(tampered_result["error_stage"], "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")

    def test_12_worked_synthetic_credential_specification(self):
        """
        Validates worked synthetic credential construction under Protocol xeno-merkle-mldsa-v2,
        verifying exact domain-separated Merkle Root R and Authenticated Envelope Message M.
        """
        worked = SelectiveDisclosureEngine.generate_worked_synthetic_credential()
        self.assertEqual(len(worked["leaves"]), 6)
        self.assertEqual(worked["merkle_root"], "1ef26b1f079a0f6342c9b0d879717d96042dd55731928305459430e064c4b887")
        self.assertEqual(worked["authenticated_message_m"], "2900e9a0e12405157ddbc6074c9e0928fcdc2cbf15704b44e676a9498a1eba6e")

    def test_13_classical_ecdsa_baseline_verification(self):
        """
        Validates classical ECDSA secp256k1 baseline issuance and selective disclosure
        under strict fail-closed defaults.
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
        proof = self._fresh_proof(cred_obj, ["fullName"])
        result = self._verify_packet(proof)
        self.assertTrue(result["valid"])
        self.assertEqual(result["status"], "CRYPTOGRAPHICALLY_VERIFIED")

    # =========================================================================
    # TARGETED REGRESSION TEST CASES (Dr. Luigi La Spada Review, Nov 13, Page 11)
    # =========================================================================

    def test_regression_01_unknown_issuer_with_supplied_key(self):
        """
        Regression Case 1: Unknown issuer with supplied key.
        Attacker generates self-signed keypair and presents valid signature under a fresh challenge.
        Verifier queries DIDRegistry, fails to find issuer, and REJECTS at Stage 2
        even when the supplied key verifies the attacker-created signature.
        """
        rogue_keypair = PQCService.generate_keypair()
        proof = self._fresh_proof(self.credential_obj, ["fullName"])
        rogue_m, _ = compute_authenticated_envelope_message(
            issuer_did="did:xeno:unregistered:rogue_authority",
            credential_id=proof["credential_id"],
            subject_did=proof["subject_did"],
            merkle_root=proof["merkle_root"],
            schema_id=proof["schema_id"],
        )
        rogue_sig = PQCService.sign(rogue_m.encode("utf-8"), rogue_keypair["secret_key_b64"])

        res = self._verify_packet(
            proof,
            signature_b64=rogue_sig["signature_b64"],
            issuer_did="did:xeno:unregistered:rogue_authority",
            issuer_pk_b64=rogue_keypair["public_key_b64"],
        )
        self.assertFalse(res["valid"])
        self.assertEqual(res["error_stage"], "ISSUER_REGISTRY_VERIFICATION")
        self.assertIn("not registered or inactive in DID Registry", res["error"])

    def test_regression_02_root_only_signature_in_envelope_required_mode(self):
        """
        Regression Case 2: Root-only signature in envelope-required mode.
        Presenter supplies signature over raw root R; verifier requires envelope M and REJECTS
        at Stage 4 without falling back to root-only verification.
        """
        cred_root_only = CredentialService.issue_credential(
            issuer=self.pqc_issuer,
            subject_did="did:xeno:subject:root_only",
            attributes=self.attributes_1,
            secret_key_b64=self.pqc_secret_key,
            bind_envelope=False
        )
        cred_obj = IssuedCredential.objects.get(id=cred_root_only["credential_id"])
        proof = self._fresh_proof(cred_obj, ["fullName"])

        res = self._verify_packet(proof, envelope_required=True)
        self.assertFalse(res["valid"])
        self.assertEqual(res["error_stage"], "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")
        self.assertIn("Envelope", res["error"])

    def test_regression_03_altered_credential_or_metadata_identifier(self):
        """
        Regression Case 3: Altered credential or metadata identifier.
        Attacker alters credential_id of a revoked credential (and recomputes unkeyed token T)
        trying to bypass Stage 1 revocation; Stage 4 calculates envelope digest M'
        which diverges from signed envelope M, rejecting at Stage 4.
        """
        self.credential_obj.is_revoked = True
        self.credential_obj.revocation_reason = "Compromised credential test"
        self.credential_obj.save()

        proof = self._fresh_proof(self.credential_obj, ["fullName"])
        fake_cred_id = "11111111-2222-3333-4444-555555555555"
        forged_tok = build_replay_protection_token(
            fake_cred_id, proof["verifier_nonce"], proof["timestamp_iso"], ["fullName"]
        )
        res = self._verify_packet(proof, credential_id=fake_cred_id, replay_token=forged_tok)
        self.assertFalse(res["valid"])
        self.assertEqual(res["error_stage"], "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")

    def test_regression_04_missing_or_unknown_nonce(self):
        """
        Regression Case 4: Missing or unknown nonce.
        Both missing nonce and fabricated unissued nonce (even with recomputed token T)
        are rejected at Stage 0.
        """
        proof = VerificationService.generate_disclosure_proof(
            credential=self.credential_obj,
            disclosed_keys=["fullName"]
        )
        # 1. Missing nonce
        res_missing = self._verify_packet(proof, verifier_nonce=None, replay_token=None)
        self.assertFalse(res_missing["valid"])
        self.assertEqual(res_missing["error_stage"], "REPLAY_PROTECTION")
        self.assertIn("Missing mandatory verifier challenge nonce", res_missing["error"])

        # 2. Unknown/fabricated nonce with recomputed unkeyed token
        fabricated_nonce = "fedcba9876543210fedcba9876543210"
        timestamp = timezone.now().isoformat()
        token = build_replay_protection_token(
            credential_id=proof["credential_id"],
            verifier_nonce=fabricated_nonce,
            timestamp_iso=timestamp,
            disclosed_keys=["fullName"]
        )
        res_unknown = self._verify_packet(
            proof,
            verifier_nonce=fabricated_nonce,
            timestamp_iso=timestamp,
            replay_token=token,
        )
        self.assertFalse(res_unknown["valid"])
        self.assertEqual(res_unknown["error_stage"], "REPLAY_PROTECTION")
        self.assertIn("not found or unissued", res_unknown["error"])

    def test_regression_05_absent_token_or_wrong_verifier_audience(self):
        """
        Regression Case 5: Absent or invalid replay token.
        Tests both missing replay_token and invalid/mismatched token rejection at Stage 0.
        Note: Verifier audience binding is not implemented in T (documented limitation).
        """
        # 1. Absent replay_token with valid issued nonce
        proof_no_tok = self._fresh_proof(self.credential_obj, ["fullName"])
        res_absent = self._verify_packet(proof_no_tok, replay_token=None)
        self.assertFalse(res_absent["valid"])
        self.assertEqual(res_absent["error_stage"], "REPLAY_PROTECTION")
        self.assertIn("Missing mandatory replay protection token", res_absent["error"])

        # 2. Mismatched / invalid replay_token with valid issued nonce
        proof_bad_tok = self._fresh_proof(self.credential_obj, ["fullName"])
        res_bad = self._verify_packet(proof_bad_tok, replay_token="0" * 64)
        self.assertFalse(res_bad["valid"])
        self.assertEqual(res_bad["error_stage"], "REPLAY_PROTECTION")
        self.assertIn("Replay protection token invalid", res_bad["error"])

    def test_regression_06_expired_or_reused_nonce(self):
        """
        Regression Case 6: Expired or reused nonce.
        Validates state transitions: active -> consumed, active -> expired.
        """
        proof = self._fresh_proof(self.credential_obj, ["fullName"])

        res1 = self._verify_packet(proof)
        self.assertTrue(res1["valid"])

        res2 = self._verify_packet(proof)
        self.assertFalse(res2["valid"])
        self.assertEqual(res2["error_stage"], "REPLAY_PROTECTION")
        self.assertIn("already consumed", res2["error"])

        expired_nonce_obj = VerifierNonce.objects.create(
            nonce="expired_nonce_test_1234567890abcdef",
            expires_at=timezone.now() - timedelta(seconds=10),
            is_consumed=False
        )
        exp_ts = timezone.now().isoformat()
        exp_tok = build_replay_protection_token(
            proof["credential_id"], expired_nonce_obj.nonce, exp_ts, ["fullName"]
        )
        res_expired = self._verify_packet(
            proof,
            verifier_nonce=expired_nonce_obj.nonce,
            timestamp_iso=exp_ts,
            replay_token=exp_tok,
        )
        self.assertFalse(res_expired["valid"])
        self.assertEqual(res_expired["error_stage"], "REPLAY_PROTECTION")
        self.assertIn("expired", res_expired["error"])

    def test_regression_07_ambiguous_or_differently_typed_claim(self):
        """
        Regression Case 7: Ambiguous delimiter and differently typed claim (Protocol v2).
        1. Colons/whitespace in keys are rejected with ValueError under restrictive key schema.
        2. JSON scalar types are preserved so integer 18 and string "18" produce distinct leaf hashes.
        """
        salt = "0123456789abcdef0123456789abcdef"
        with self.assertRaises(ValueError):
            canonical_attribute_encoding("a:b", "c", salt)

        encoded_clean = canonical_attribute_encoding("cleanKey", "c", salt)
        self.assertEqual(encoded_clean, b'\x00["cleanKey","c","0123456789abcdef0123456789abcdef"]')

        h_str = hash_leaf("age", "18", salt)
        h_int = hash_leaf("age", 18, salt)
        self.assertNotEqual(h_str, h_int)

    def test_regression_08_invalid_signature_then_valid_retry_nonce_lifecycle(self):
        """
        Regression Case 8: Invalid signature then valid retry.
        Documents early Stage-0 nonce consumption: failed Stage-4 attempt consumes the nonce,
        so immediate retry with the valid signature using the same nonce is rejected at Stage 0.
        """
        proof = self._fresh_proof(self.credential_obj, ["fullName"])
        tampered_sig = "A" * len(proof["signature_b64"])

        res_fail = self._verify_packet(proof, signature_b64=tampered_sig)
        self.assertFalse(res_fail["valid"])
        self.assertEqual(res_fail["error_stage"], "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")

        nonce_record = VerifierNonce.objects.get(nonce=proof["verifier_nonce"])
        self.assertTrue(nonce_record.is_consumed)

        res_retry = self._verify_packet(proof)
        self.assertFalse(res_retry["valid"])
        self.assertEqual(res_retry["error_stage"], "REPLAY_PROTECTION")
        self.assertIn("already consumed", res_retry["error"])

    def test_regression_09_http_api_fail_closed_enforcement(self):
        """
        Regression Case 9: End-to-end HTTP API fail-closed verification on /api/proofs/verify/.
        Confirms live REST endpoint enforces nonce/token, registry key lookup, and envelope signature.
        """
        client = APIClient()

        # 1. Valid fail-closed HTTP flow
        nonce_resp = client.post("/api/verifier/nonce/", data={}, format="json")
        self.assertEqual(nonce_resp.status_code, 200)
        nonce_val = nonce_resp.json()["verifier_nonce"]

        proof_resp = client.post(
            "/api/proofs/generate/",
            data={
                "credential_id": str(self.credential_obj.id),
                "disclosed_keys": ["fullName", "nationality"],
                "verifier_nonce": nonce_val,
            },
            format="json",
        )
        self.assertEqual(proof_resp.status_code, 200)
        packet = proof_resp.json()

        verify_ok = client.post("/api/proofs/verify/", data=packet, format="json")
        self.assertEqual(verify_ok.status_code, 200)
        self.assertTrue(verify_ok.json()["valid"])
        self.assertEqual(verify_ok.json()["verified_target"], "AUTHENTICATED_ENVELOPE")

        # 2. Missing nonce via HTTP -> HTTP 400 REPLAY_PROTECTION
        bad_no_nonce = copy.deepcopy(packet)
        bad_no_nonce.pop("verifier_nonce", None)
        res_no_nonce = client.post("/api/proofs/verify/", data=bad_no_nonce, format="json")
        self.assertEqual(res_no_nonce.status_code, 400)
        self.assertEqual(res_no_nonce.json()["error_stage"], "REPLAY_PROTECTION")

        # 3. Root-only credential via HTTP -> HTTP 400 CRYPTOGRAPHIC_SIGNATURE_VERIFICATION
        cred_root = CredentialService.issue_credential(
            issuer=self.pqc_issuer,
            subject_did="did:xeno:subject:http_root_only",
            attributes=self.attributes_1,
            secret_key_b64=self.pqc_secret_key,
            bind_envelope=False,
        )
        nonce2 = client.post("/api/verifier/nonce/", data={}, format="json").json()["verifier_nonce"]
        root_pkt = client.post(
            "/api/proofs/generate/",
            data={
                "credential_id": cred_root["credential_id"],
                "disclosed_keys": ["fullName"],
                "verifier_nonce": nonce2,
            },
            format="json",
        ).json()
        res_root = client.post("/api/proofs/verify/", data=root_pkt, format="json")
        self.assertEqual(res_root.status_code, 400)
        self.assertEqual(res_root.json()["error_stage"], "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")

        # 4. Delimiter colon key via /api/credentials/issue/ -> HTTP 400
        bad_issue = client.post(
            "/api/credentials/issue/",
            data={
                "issuer_did": self.pqc_issuer.did,
                "secret_key_b64": self.pqc_secret_key,
                "attributes": {"a:b": "c"},
            },
            format="json",
        )
        self.assertEqual(bad_issue.status_code, 400)
