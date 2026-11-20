#!/usr/bin/env python3
"""
Automated 450-Trial Negative Testing, Regression & Privacy Audit Runner (Protocol: xeno-merkle-mldsa-v2).

- 9 malformed-input attack categories x 50 randomized iterations = 450 negative trials
- Fresh valid verifier nonce + replay_token supplied to every non-Stage-0 test so Stage 0
  does not mask Stage 1-4 controls
- Live execution (never hardcoded) of all 8 targeted regression cases + Case 9 HTTP API check
- Separate execution of Privacy Observations PRI-01 (independent issuance salt divergence) and
  PRI-02 (repeated-presentation root/signature linkability) kept strictly separate from attack counts

Output:
- docs/latest/negative_test_execution_450.log
"""

import copy
import math
import os
import random
import secrets
import sys
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone as dt_tz

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend_django.settings")

import django
django.setup()

from django.utils import timezone
from rest_framework.test import APIClient
from core_identity.models import IssuedCredential, VerifierNonce
from core_identity.crypto_service import PQCService
from core_identity.merkle_engine import (
    PROTOCOL_VERSION,
    canonical_attribute_encoding,
    compute_authenticated_envelope_message,
    build_replay_protection_token,
    hash_leaf,
)
from core_identity.services.issuer_service import IssuerService
from core_identity.services.credential_service import CredentialService
from core_identity.services.verification_service import VerificationService
from run_feasibility_100 import collect_environment_metadata


def shannon_entropy_bits_per_byte(data_bytes: bytes) -> float:
    counts = Counter(data_bytes)
    n = len(data_bytes)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def main():
    env_meta = collect_environment_metadata()
    hw = env_meta["hardware"]
    rt = env_meta["runtime"]
    run_ts = datetime.now(dt_tz.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print("=" * 90)
    print(f"XENOVERIFY 450-TRIAL NEGATIVE TESTING & REGRESSION BATTERY ({PROTOCOL_VERSION})")
    print(f"Execution Date / Time: {run_ts}")
    print(f"Host: {hw['model']} ({hw['hostname']}) | {hw['cpu']} | {hw['ram_gb']} GB RAM")
    print("=" * 90)

    issuer_pqc, pqc_kp = IssuerService.initialize_issuer(
        scheme="ML-DSA-65 (NIST FIPS 204)",
        entity_name="Negative Test Battery Authority",
    )
    pqc_sk = pqc_kp["secret_key_b64"]
    created_nonces = []

    def fresh_challenge(cred_id, keys):
        n = VerificationService.create_verifier_nonce(validity_seconds=300)["verifier_nonce"]
        created_nonces.append(n)
        ts_iso = timezone.now().isoformat()
        tok = build_replay_protection_token(str(cred_id), n, ts_iso, keys)
        return n, ts_iso, tok

    attrs_primary = {
        "fullName": "Alex Carter",
        "nin": "29837492812",
        "dob": "1992-06-14",
        "nationality": "Nigerian",
        "clearanceLevel": "Tier-3",
        "residence": "Victoria Island, Lagos",
    }
    attrs_secondary = {
        "fullName": "Amina Bello",
        "nin": "83749201837",
        "dob": "1995-11-23",
        "nationality": "Nigerian",
        "clearanceLevel": "Tier-1",
        "residence": "Maitama, Abuja",
    }

    log_lines = [
        "=" * 95,
        f"XENOVERIFY NEGATIVE SECURITY & REGRESSION EXECUTION LOG ({PROTOCOL_VERSION})",
        f"Execution Timestamp: {run_ts}",
        f"Host Machine: {hw['model']} (Hostname: {hw['hostname']})",
        f"Processor & RAM: {hw['cpu']} ({hw['logical_cpus']} logical CPUs), {hw['ram_gb']} GB RAM",
        f"OS & Runtime: {hw['os']} | Python {rt['python_version']} | Django {rt['packages'].get('Django')} | dilithium-py {rt['packages'].get('dilithium-py')}",
        f"Git HEAD Commit: {env_meta['git']['head_commit']} (Working tree dirty/v2 hardened: {env_meta['git']['working_tree_modified_beyond_head']})",
        "Verification Mode: STRICT FAIL-CLOSED (require_registry_check=True, envelope_required=True, require_nonce=True, require_replay_token=True)",
        "Total Negative Trials: 450 (50 randomized iterations x 9 malformed-input attack vectors AV1-AV9)",
        "=" * 95,
        "",
    ]

    try:
        cred_pqc = CredentialService.issue_credential(
            issuer=issuer_pqc,
            subject_did="did:xeno:subject:001",
            attributes=attrs_primary,
            secret_key_b64=pqc_sk,
            bind_envelope=True,
        )
        cred_obj = IssuedCredential.objects.get(id=cred_pqc["credential_id"])

        cred_pqc_2 = CredentialService.issue_credential(
            issuer=issuer_pqc,
            subject_did="did:xeno:subject:002",
            attributes=attrs_secondary,
            secret_key_b64=pqc_sk,
            bind_envelope=True,
        )
        cred_obj_2 = IssuedCredential.objects.get(id=cred_pqc_2["credential_id"])

        base_keys = ["fullName", "nationality"]
        base_proof = VerificationService.generate_disclosure_proof(cred_obj, disclosed_keys=base_keys)
        proof_2_same_keys = VerificationService.generate_disclosure_proof(cred_obj_2, disclosed_keys=base_keys)

        vectors = [
            ("AV1", "Injected Leaf Tampering", "MERKLE_PROOF_INCLUSION", 3),
            ("AV2", "Corrupted Sibling Proof Path", "MERKLE_PROOF_INCLUSION", 3),
            ("AV3", "Corrupted ML-DSA-65 Signature", "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION", 4),
            ("AV4", "Substituted Merkle Root (Stage 3 & Stage 4)", "MERKLE_PROOF_INCLUSION_OR_SIG", 4),
            ("AV5", "Cross-Credential Attribute Splicing", "MERKLE_PROOF_INCLUSION", 3),
            ("AV6", "Revoked Credential Circumvention", "REVOCATION_CHECK", 1),
            ("AV7", "Challenge Nonce Replay / Expiration / Unknown", "REPLAY_PROTECTION", 0),
            ("AV8", "Unknown Issuer DID or Substituted Public Key", "ISSUER_REGISTRY_VERIFICATION", 2),
            ("AV9", "Authenticated Envelope Metadata Tampering", "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION", 4),
        ]

        total_executed = 0
        total_rejected = 0
        vector_summaries = {}

        for vec_id, vec_name, target_stage_name, stage_num in vectors:
            print(f"[*] Running 50 trials for {vec_id}: {vec_name}...")
            log_lines.append(f"--- ATTACK VECTOR {vec_id}: {vec_name} (Expected Target: Stage {stage_num} - {target_stage_name}) ---")
            log_lines.append(f"{'Trial':<8} {'Timestamp':<24} {'Injected Anomaly':<46} {'Observed Stage':<34} {'Result'}")
            log_lines.append("-" * 125)
            vec_rejected = 0

            for i in range(1, 51):
                total_executed += 1
                trial_id = f"{vec_id}-{i:02d}"
                ts_log = datetime.now(dt_tz.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

                if vec_id == "AV1":
                    nonce, ts_iso, tok = fresh_challenge(cred_obj.id, base_keys)
                    claims = copy.deepcopy(base_proof["disclosed_claims"])
                    sfx = secrets.token_hex(4)
                    claims[0]["value"] = f"Alex Carter_{sfx}"
                    anomaly_desc = f"Altered fullName (+{sfx})"
                    res = VerificationService.verify_proof_package(
                        merkle_root=base_proof["merkle_root"], signature_b64=base_proof["signature_b64"],
                        issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                        disclosed_claims=claims, credential_id=base_proof["credential_id"],
                        subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                        verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                    )
                    is_rejected = (not res["valid"]) and (res.get("error_stage") == "MERKLE_PROOF_INCLUSION")

                elif vec_id == "AV2":
                    nonce, ts_iso, tok = fresh_challenge(cred_obj.id, base_keys)
                    claims = copy.deepcopy(base_proof["disclosed_claims"])
                    claims[0]["proof_path"][0]["sibling_hash"] = secrets.token_hex(32)
                    anomaly_desc = "Corrupted level-0 sibling hash"
                    res = VerificationService.verify_proof_package(
                        merkle_root=base_proof["merkle_root"], signature_b64=base_proof["signature_b64"],
                        issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                        disclosed_claims=claims, credential_id=base_proof["credential_id"],
                        subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                        verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                    )
                    is_rejected = (not res["valid"]) and (res.get("error_stage") == "MERKLE_PROOF_INCLUSION")

                elif vec_id == "AV3":
                    nonce, ts_iso, tok = fresh_challenge(cred_obj.id, base_keys)
                    sig_chars = list(base_proof["signature_b64"])
                    flip_idx = random.randint(10, len(sig_chars) - 10)
                    sig_chars[flip_idx] = "Z" if sig_chars[flip_idx] != "Z" else "A"
                    anomaly_desc = f"Mutated signature char at offset {flip_idx}"
                    res = VerificationService.verify_proof_package(
                        merkle_root=base_proof["merkle_root"], signature_b64="".join(sig_chars),
                        issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                        disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
                        subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                        verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                    )
                    is_rejected = (not res["valid"]) and (res.get("error_stage") == "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")

                elif vec_id == "AV4":
                    nonce, ts_iso, tok = fresh_challenge(cred_obj.id, base_keys)
                    if i <= 25:
                        # Substituted root with matching claims from cred 2 -> passes Stage 3, caught at Stage 4 Envelope
                        anomaly_desc = "Cred-2 root+claims under Cred-1 envelope sig"
                        res = VerificationService.verify_proof_package(
                            merkle_root=proof_2_same_keys["merkle_root"], signature_b64=base_proof["signature_b64"],
                            issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                            disclosed_claims=proof_2_same_keys["disclosed_claims"], credential_id=base_proof["credential_id"],
                            subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                            verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                        )
                        is_rejected = (not res["valid"]) and (res.get("error_stage") == "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")
                    else:
                        sub_root = secrets.token_hex(32)
                        anomaly_desc = f"Random substituted root ({sub_root[:10]}...)"
                        res = VerificationService.verify_proof_package(
                            merkle_root=sub_root, signature_b64=base_proof["signature_b64"],
                            issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                            disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
                            subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                            verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                        )
                        is_rejected = (not res["valid"]) and (res.get("error_stage") == "MERKLE_PROOF_INCLUSION")

                elif vec_id == "AV5":
                    spliced_keys = ["fullName", "residence"]
                    nonce, ts_iso, tok = fresh_challenge(cred_obj.id, spliced_keys)
                    proof_res = VerificationService.generate_disclosure_proof(cred_obj_2, disclosed_keys=["residence"])
                    spliced_claims = [base_proof["disclosed_claims"][0], proof_res["disclosed_claims"][0]]
                    anomaly_desc = "Spliced leaf 'residence' from subject:002"
                    res = VerificationService.verify_proof_package(
                        merkle_root=base_proof["merkle_root"], signature_b64=base_proof["signature_b64"],
                        issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                        disclosed_claims=spliced_claims, credential_id=base_proof["credential_id"],
                        subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                        verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                    )
                    is_rejected = (not res["valid"]) and (res.get("error_stage") == "MERKLE_PROOF_INCLUSION")

                elif vec_id == "AV6":
                    nonce, ts_iso, tok = fresh_challenge(cred_obj.id, base_keys)
                    IssuedCredential.objects.filter(id=cred_obj.id).update(is_revoked=True, revocation_reason="Simulated compromise")
                    anomaly_desc = f"Revoked credential {str(cred_obj.id)[:8]}..."
                    res = VerificationService.verify_proof_package(
                        merkle_root=base_proof["merkle_root"], signature_b64=base_proof["signature_b64"],
                        issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                        disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
                        subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                        verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                    )
                    IssuedCredential.objects.filter(id=cred_obj.id).update(is_revoked=False)
                    is_rejected = (not res["valid"]) and (res.get("error_stage") == "REVOCATION_CHECK")

                elif vec_id == "AV7":
                    ts_iso = timezone.now().isoformat()
                    if i <= 20:
                        nonce = VerificationService.create_verifier_nonce(validity_seconds=300)["verifier_nonce"]
                        created_nonces.append(nonce)
                        VerifierNonce.objects.filter(nonce=nonce).update(is_consumed=True, consumed_at=timezone.now())
                        anomaly_desc = f"Replayed consumed nonce {nonce[:10]}..."
                    elif i <= 35:
                        nonce = f"exp_{secrets.token_hex(14)}"
                        created_nonces.append(nonce)
                        VerifierNonce.objects.create(
                            nonce=nonce,
                            expires_at=timezone.now() - timedelta(seconds=random.randint(10, 100)),
                            is_consumed=False,
                        )
                        anomaly_desc = "Expired verifier challenge nonce"
                    else:
                        nonce = f"unissued_{secrets.token_hex(12)}"
                        anomaly_desc = "Unissued nonce w/ recomputed unkeyed token"
                    tok = build_replay_protection_token(str(cred_obj.id), nonce, ts_iso, base_keys)
                    res = VerificationService.verify_proof_package(
                        merkle_root=base_proof["merkle_root"], signature_b64=base_proof["signature_b64"],
                        issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                        disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
                        subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                        verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                    )
                    is_rejected = (not res["valid"]) and (res.get("error_stage") == "REPLAY_PROTECTION")

                elif vec_id == "AV8":
                    nonce, ts_iso, tok = fresh_challenge(cred_obj.id, base_keys)
                    if i <= 25:
                        rogue_did = f"did:xeno:unregistered:{secrets.token_hex(8)}"
                        rogue_kp = PQCService.generate_keypair()
                        rogue_m, _ = compute_authenticated_envelope_message(
                            rogue_did, str(cred_obj.id), base_proof["subject_did"],
                            base_proof["merkle_root"], base_proof["schema_id"],
                        )
                        rogue_sig = PQCService.sign(rogue_m.encode("utf-8"), rogue_kp["secret_key_b64"])
                        anomaly_desc = f"Unregistered DID w/ self-signed rogue key"
                        res = VerificationService.verify_proof_package(
                            merkle_root=base_proof["merkle_root"], signature_b64=rogue_sig["signature_b64"],
                            issuer_did=rogue_did, issuer_pk_b64=rogue_kp["public_key_b64"],
                            disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
                            subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                            verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                        )
                    else:
                        rogue_kp = PQCService.generate_keypair()
                        anomaly_desc = "Substituted public key under legitimate DID"
                        res = VerificationService.verify_proof_package(
                            merkle_root=base_proof["merkle_root"], signature_b64=base_proof["signature_b64"],
                            issuer_did=base_proof["issuer_did"], issuer_pk_b64=rogue_kp["public_key_b64"],
                            disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
                            subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                            verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                        )
                    is_rejected = (not res["valid"]) and (res.get("error_stage") == "ISSUER_REGISTRY_VERIFICATION")

                elif vec_id == "AV9":
                    mod_choice = i % 3
                    if mod_choice == 0:
                        tampered_cid = str(uuid.uuid4())
                        nonce, ts_iso, tok = fresh_challenge(tampered_cid, base_keys)
                        anomaly_desc = "Altered credential_id in envelope M"
                        res = VerificationService.verify_proof_package(
                            merkle_root=base_proof["merkle_root"], signature_b64=base_proof["signature_b64"],
                            issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                            disclosed_claims=base_proof["disclosed_claims"], credential_id=tampered_cid,
                            subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
                            verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                        )
                    elif mod_choice == 1:
                        nonce, ts_iso, tok = fresh_challenge(cred_obj.id, base_keys)
                        anomaly_desc = "Altered subject_did in envelope M"
                        res = VerificationService.verify_proof_package(
                            merkle_root=base_proof["merkle_root"], signature_b64=base_proof["signature_b64"],
                            issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                            disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
                            subject_did=f"did:xeno:subject:attacker_{secrets.token_hex(4)}", schema_id=base_proof["schema_id"],
                            verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                        )
                    else:
                        nonce, ts_iso, tok = fresh_challenge(cred_obj.id, base_keys)
                        anomaly_desc = "Altered schema_id in envelope M"
                        res = VerificationService.verify_proof_package(
                            merkle_root=base_proof["merkle_root"], signature_b64=base_proof["signature_b64"],
                            issuer_did=base_proof["issuer_did"], issuer_pk_b64=base_proof["issuer_public_key_b64"],
                            disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
                            subject_did=base_proof["subject_did"], schema_id="urn:xeno:schema:malicious:v99",
                            verifier_nonce=nonce, timestamp_iso=ts_iso, replay_token=tok,
                        )
                    is_rejected = (not res["valid"]) and (res.get("error_stage") == "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION")

                assert is_rejected, f"Unexpected verification outcome in {trial_id}: {res}"
                vec_rejected += 1
                total_rejected += 1
                stage_obs = res.get("error_stage", "NONE")
                log_lines.append(f"{trial_id:<8} {ts_log:<24} {anomaly_desc:<46} {stage_obs:<34} REJECTED [{stage_obs}]")

            vector_summaries[vec_id] = (vec_name, stage_num, 50, vec_rejected)
            log_lines.append("")

        # Live execution of the 9 Targeted Regression Cases
        log_lines.append("=" * 95)
        log_lines.append("LIVE TARGETED REGRESSION CHECKS (DR. LUIGI REVIEW, PAGE 11 + HTTP API CHECK)")
        log_lines.append("=" * 95)
        log_lines.append(f"{'Case':<8} {'Description':<50} {'Observed Stage':<36} {'Outcome'}")
        log_lines.append("-" * 110)

        reg_results = []
        # R1 Unknown issuer w/ valid self-signed attacker sig
        r1_kp = PQCService.generate_keypair()
        n1, ts1, t1 = fresh_challenge(cred_obj.id, base_keys)
        r1_m, _ = compute_authenticated_envelope_message("did:xeno:rogue:01", str(cred_obj.id), base_proof["subject_did"], base_proof["merkle_root"], base_proof["schema_id"])
        r1_sig = PQCService.sign(r1_m.encode("utf-8"), r1_kp["secret_key_b64"])
        res1 = VerificationService.verify_proof_package(
            base_proof["merkle_root"], r1_sig["signature_b64"], r1_kp["public_key_b64"], "did:xeno:rogue:01",
            disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
            subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
            verifier_nonce=n1, timestamp_iso=ts1, replay_token=t1,
        )
        assert not res1["valid"] and res1["error_stage"] == "ISSUER_REGISTRY_VERIFICATION"
        reg_results.append(("REG-01", "Unknown issuer with supplied key", res1["error_stage"], "PASS (Rejected)"))

        # R2 Root-only signature in strict envelope mode
        c_root = CredentialService.issue_credential(issuer_pqc, "did:xeno:subj:rootonly", attrs_primary, pqc_sk, bind_envelope=False)
        co_root = IssuedCredential.objects.get(id=c_root["credential_id"])
        n2 = VerificationService.create_verifier_nonce(300)["verifier_nonce"]; created_nonces.append(n2)
        p_root = VerificationService.generate_disclosure_proof(co_root, ["fullName"], verifier_nonce=n2)
        res2 = VerificationService.verify_proof_package(
            p_root["merkle_root"], p_root["signature_b64"], p_root["issuer_public_key_b64"], p_root["issuer_did"],
            disclosed_claims=p_root["disclosed_claims"], credential_id=p_root["credential_id"],
            subject_did=p_root["subject_did"], schema_id=p_root["schema_id"],
            verifier_nonce=p_root["verifier_nonce"], timestamp_iso=p_root["timestamp_iso"], replay_token=p_root["replay_token"],
        )
        assert not res2["valid"] and res2["error_stage"] == "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION"
        reg_results.append(("REG-02", "Root-only sig in envelope-required mode", res2["error_stage"], "PASS (Rejected)"))

        # R3 Altered credential_id trying to evade revocation
        IssuedCredential.objects.filter(id=cred_obj.id).update(is_revoked=True)
        n3, ts3, t3 = fresh_challenge("99999999-8888-7777-6666-555555555555", base_keys)
        res3 = VerificationService.verify_proof_package(
            base_proof["merkle_root"], base_proof["signature_b64"], base_proof["issuer_public_key_b64"], base_proof["issuer_did"],
            disclosed_claims=base_proof["disclosed_claims"], credential_id="99999999-8888-7777-6666-555555555555",
            subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
            verifier_nonce=n3, timestamp_iso=ts3, replay_token=t3,
        )
        IssuedCredential.objects.filter(id=cred_obj.id).update(is_revoked=False)
        assert not res3["valid"] and res3["error_stage"] == "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION"
        reg_results.append(("REG-03", "Altered credential_id on revoked cred", res3["error_stage"], "PASS (Rejected)"))

        # R4 Missing / unknown nonce with recomputed token
        res4 = VerificationService.verify_proof_package(
            base_proof["merkle_root"], base_proof["signature_b64"], base_proof["issuer_public_key_b64"], base_proof["issuer_did"],
            disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
            subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
        )
        assert not res4["valid"] and res4["error_stage"] == "REPLAY_PROTECTION"
        reg_results.append(("REG-04", "Missing or unissued verifier nonce", res4["error_stage"], "PASS (Rejected)"))

        # R5 Absent replay token
        n5 = VerificationService.create_verifier_nonce(300)["verifier_nonce"]; created_nonces.append(n5)
        res5 = VerificationService.verify_proof_package(
            base_proof["merkle_root"], base_proof["signature_b64"], base_proof["issuer_public_key_b64"], base_proof["issuer_did"],
            disclosed_claims=base_proof["disclosed_claims"], credential_id=base_proof["credential_id"],
            subject_did=base_proof["subject_did"], schema_id=base_proof["schema_id"],
            verifier_nonce=n5, timestamp_iso=timezone.now().isoformat(), replay_token=None,
        )
        assert not res5["valid"] and res5["error_stage"] == "REPLAY_PROTECTION"
        reg_results.append(("REG-05", "Absent replay_token (aud binding noted)", res5["error_stage"], "PASS (Rejected)"))

        # R6 Reused nonce
        n6 = VerificationService.create_verifier_nonce(300)["verifier_nonce"]; created_nonces.append(n6)
        p6 = VerificationService.generate_disclosure_proof(cred_obj, ["fullName"], verifier_nonce=n6)
        r6a = VerificationService.verify_proof_package(
            p6["merkle_root"], p6["signature_b64"], p6["issuer_public_key_b64"], p6["issuer_did"],
            disclosed_claims=p6["disclosed_claims"], credential_id=p6["credential_id"],
            subject_did=p6["subject_did"], schema_id=p6["schema_id"],
            verifier_nonce=p6["verifier_nonce"], timestamp_iso=p6["timestamp_iso"], replay_token=p6["replay_token"],
        )
        r6b = VerificationService.verify_proof_package(
            p6["merkle_root"], p6["signature_b64"], p6["issuer_public_key_b64"], p6["issuer_did"],
            disclosed_claims=p6["disclosed_claims"], credential_id=p6["credential_id"],
            subject_did=p6["subject_did"], schema_id=p6["schema_id"],
            verifier_nonce=p6["verifier_nonce"], timestamp_iso=p6["timestamp_iso"], replay_token=p6["replay_token"],
        )
        assert r6a["valid"] and (not r6b["valid"]) and r6b["error_stage"] == "REPLAY_PROTECTION"
        reg_results.append(("REG-06", "Consumed / expired nonce reuse", r6b["error_stage"], "PASS (Rejected)"))

        # R7 Ambiguous delimiter & distinct type commitment
        salt_r7 = "0123456789abcdef0123456789abcdef"
        colon_raised = False
        try:
            canonical_attribute_encoding("a:b", "c", salt_r7)
        except ValueError:
            colon_raised = True
        h_int = hash_leaf("age", 18, salt_r7)
        h_str = hash_leaf("age", "18", salt_r7)
        assert colon_raised and (h_int != h_str)
        reg_results.append(("REG-07", "Colon delimiter + distinct int/str types", "ValueError + H(18)!=H('18')", "PASS (Enforced)"))

        # R8 Failed Stage-4 attempt burns nonce on Stage-0 entry
        n8 = VerificationService.create_verifier_nonce(300)["verifier_nonce"]; created_nonces.append(n8)
        p8 = VerificationService.generate_disclosure_proof(cred_obj, ["fullName"], verifier_nonce=n8)
        r8_fail = VerificationService.verify_proof_package(
            p8["merkle_root"], "A" * len(p8["signature_b64"]), p8["issuer_public_key_b64"], p8["issuer_did"],
            disclosed_claims=p8["disclosed_claims"], credential_id=p8["credential_id"],
            subject_did=p8["subject_did"], schema_id=p8["schema_id"],
            verifier_nonce=p8["verifier_nonce"], timestamp_iso=p8["timestamp_iso"], replay_token=p8["replay_token"],
        )
        r8_retry = VerificationService.verify_proof_package(
            p8["merkle_root"], p8["signature_b64"], p8["issuer_public_key_b64"], p8["issuer_did"],
            disclosed_claims=p8["disclosed_claims"], credential_id=p8["credential_id"],
            subject_did=p8["subject_did"], schema_id=p8["schema_id"],
            verifier_nonce=p8["verifier_nonce"], timestamp_iso=p8["timestamp_iso"], replay_token=p8["replay_token"],
        )
        assert (not r8_fail["valid"]) and (not r8_retry["valid"]) and r8_retry["error_stage"] == "REPLAY_PROTECTION"
        reg_results.append(("REG-08", "Invalid sig burns nonce; retry blocked", r8_retry["error_stage"], "PASS (Confirmed)"))

        # R9 Live HTTP API fail-closed check via DRF APIClient
        client = APIClient()
        n9_http = client.post("/api/verifier/nonce/", data={}, format="json").json()["verifier_nonce"]
        created_nonces.append(n9_http)
        p9_http = client.post("/api/proofs/generate/", data={"credential_id": str(cred_obj.id), "disclosed_keys": ["fullName"], "verifier_nonce": n9_http}, format="json").json()
        res_http_ok = client.post("/api/proofs/verify/", data=p9_http, format="json")
        bad_http = copy.deepcopy(p9_http); bad_http.pop("verifier_nonce", None)
        res_http_bad = client.post("/api/proofs/verify/", data=bad_http, format="json")
        assert res_http_ok.status_code == 200 and res_http_bad.status_code == 400
        reg_results.append(("REG-09", "HTTP /api/proofs/verify/ fail-closed", "HTTP 200 valid / HTTP 400 blocked", "PASS (Confirmed)"))

        for cid, cdesc, cstg, cstat in reg_results:
            log_lines.append(f"{cid:<8} {cdesc:<50} {cstg:<36} {cstat}")
        log_lines.append("")

        # Separate Privacy & Entropy Observations (NOT counted in 450/450 attack rejection)
        raw_salts = b"".join(os.urandom(16) for _ in range(100))
        ent_bpb = shannon_entropy_bits_per_byte(raw_salts)
        c_pa = CredentialService.issue_credential(issuer_pqc, "did:xeno:pri:a", {"nationality": "Nigerian"}, pqc_sk)
        c_pb = CredentialService.issue_credential(issuer_pqc, "did:xeno:pri:b", {"nationality": "Nigerian"}, pqc_sk)
        pres_1 = VerificationService.generate_disclosure_proof(cred_obj, ["fullName"])
        pres_2 = VerificationService.generate_disclosure_proof(cred_obj, ["nationality"])
        assert c_pa["merkle_root"] != c_pb["merkle_root"]
        assert pres_1["merkle_root"] == pres_2["merkle_root"] and pres_1["signature_b64"] == pres_2["signature_b64"]

        log_lines.extend([
            "=" * 95,
            "SEPARATE PRIVACY & LINKABILITY OBSERVATIONS (EXCLUDED FROM 450-TRIAL REJECTION COUNTS)",
            "=" * 95,
            f"PRI-01 (Independent issuance commitment divergence): Distinct 128-bit CSPRNG salts yield distinct roots (R_A={c_pa['merkle_root'][:16]}... != R_B={c_pb['merkle_root'][:16]}...); measured 1600-byte os.urandom entropy = {ent_bpb:.4f} bits/byte.",
            f"PRI-02 (Repeated presentation linkability limit): Two subset presentations of cred {cred_obj.id} expose identical static root R={pres_1['merkle_root'][:16]}... and identical signature -> presentations of the same credential remain linkable.",
            "",
            "=" * 95,
            "SUMMARY OF 450 MALFORMED-INPUT SECURITY TRIALS (AV1-AV9)",
            "=" * 95,
            f"{'Vector':<6} {'Attack Category Name':<46} {'Stage':<8} {'Trials':<8} {'Rejected':<10} {'Rate'}",
            "-" * 95,
        ])
        for vid, (vname, stg, tr, rej) in vector_summaries.items():
            log_lines.append(f"{vid:<6} {vname:<46} Stage {stg:<2} {tr:<8} {rej:<10} {(rej/tr)*100:.1f}%")
        log_lines.append("-" * 95)
        log_lines.append(f"{'TOTAL':<6} {'All 9 Malformed Input Vectors':<46} {'0-4':<8} {total_executed:<8} {total_rejected:<10} {(total_rejected/total_executed)*100:.1f}%")
        log_lines.append("=" * 95)
    finally:
        issuer_pqc.delete()
        VerifierNonce.objects.filter(nonce__in=created_nonces).delete()

    out_log = os.path.join(PROJECT_ROOT, "docs", "latest", "negative_test_execution_450.log")
    os.makedirs(os.path.dirname(out_log), exist_ok=True)
    with open(out_log, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")

    print(f"[+] Saved complete log to: {out_log}")
    print(f"[+] Summary: {total_rejected}/{total_executed} negative trials rejected; 9/9 regression checks passed; PRI-01 & PRI-02 logged separately.")


if __name__ == "__main__":
    main()
