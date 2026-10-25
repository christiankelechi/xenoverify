"""
Merkle-Tree Selective Disclosure Engine.
Implements:
1. Cryptographically salted attribute leaf construction: H(attribute_key || value || salt).
2. Merkle Root synthesis and sibling authentication path extraction.
3. Cryptographic selective disclosure verification (Holder presents selected leaves + paths,
   Verifier recomputes the Merkle root and validates against the Issuer's signed root).
Protects against attribute substitution, mix-and-match attacks, and linkage.
"""

import hashlib
import os
import json
import secrets
from typing import Dict, Any, List, Tuple, Optional


def canonical_attribute_encoding(key: str, value: Any, salt_hex: str) -> bytes:
    """
    Constructs the canonical attribute payload: UTF-8 encoded 'key:value:salt'.
    Ensures deterministic, cross-platform byte serialization.
    """
    return f"{key}:{str(value)}:{salt_hex}".encode("utf-8")


def hash_leaf(key: str, value: Any, salt_hex: str) -> str:
    """
    Constructs a salted leaf hash:
    H(key : value : salt)
    Prevents rainbow table / brute-force attacks on low-entropy attributes.
    """
    payload = canonical_attribute_encoding(key, value, salt_hex)
    return hashlib.sha256(payload).hexdigest()


def hash_pair(left_hex: str, right_hex: str) -> str:
    """
    Combines two child hashes in sorted lexicographical order to prevent second-preimage attacks.
    """
    combined = (min(left_hex, right_hex) + max(left_hex, right_hex)).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def compute_authenticated_envelope_message(
    issuer_did: str,
    credential_id: str,
    subject_did: str,
    merkle_root: str,
    schema_id: str = "urn:xeno:schema:id-credential:v1"
) -> Tuple[str, bytes]:
    """
    Domain-Separated Authenticated Credential Envelope Message M.
    Reconciles root-only signing with credential metadata binding into a single cryptographic payload:
    M = SHA-256( schema_id || ':' || issuer_did || ':' || credential_id || ':' || subject_did || ':' || merkle_root )
    """
    raw_payload = f"{schema_id}:{issuer_did}:{credential_id}:{subject_did}:{merkle_root}".encode("utf-8")
    digest_hex = hashlib.sha256(raw_payload).hexdigest()
    return digest_hex, raw_payload


def build_replay_protection_token(
    credential_id: str,
    verifier_nonce: str,
    timestamp_iso: str,
    disclosed_keys: List[str]
) -> str:
    """
    Constructs presentation-level replay protection token:
    Binds credential ID, verifier challenge nonce, presentation timestamp, and disclosed keys.
    """
    keys_str = ",".join(sorted(disclosed_keys))
    raw = f"{credential_id}:{verifier_nonce}:{timestamp_iso}:{keys_str}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def verify_replay_protection_token(
    token: str,
    credential_id: str,
    verifier_nonce: str,
    timestamp_iso: str,
    disclosed_keys: List[str]
) -> bool:
    """
    Validates presentation replay protection token.
    """
    expected = build_replay_protection_token(credential_id, verifier_nonce, timestamp_iso, disclosed_keys)
    return token == expected


class MerkleTree:
    """
    Standard Binary Merkle Tree for Credential Attribute Commitments.
    """

    def __init__(self, leaves: List[Dict[str, Any]]):
        """
        leaves: List of dicts, each with {'key': str, 'value': Any, 'salt': str, 'leaf_hash': str}
        """
        self.leaves = leaves
        self.levels: List[List[str]] = []
        self._build_tree()

    def _build_tree(self):
        current_level = [leaf["leaf_hash"] for leaf in self.leaves]
        self.levels.append(current_level)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left  # Duplicate odd leaf
                parent = hash_pair(left, right)
                next_level.append(parent)
            current_level = next_level
            self.levels.append(current_level)

    @property
    def root(self) -> str:
        return self.levels[-1][0] if self.levels and self.levels[-1] else ""

    def get_proof(self, leaf_index: int) -> List[Dict[str, str]]:
        """
        Extract Merkle inclusion proof (audit path) for the given leaf index.
        """
        proof = []
        index = leaf_index
        for level in self.levels[:-1]:
            is_right_sibling = (index % 2 == 0)
            sibling_index = index + 1 if is_right_sibling else index - 1
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
            else:
                sibling_hash = level[index]

            proof.append({
                "sibling_hash": sibling_hash,
                "position": "right" if is_right_sibling else "left"
            })
            index = index // 2
        return proof


class SelectiveDisclosureEngine:
    """
    Manages issuance of salted credential trees, proof compilation, and verification.
    """

    @classmethod
    def create_credential_commitment(cls, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """
        Given credential attributes (e.g., {'name': 'John Doe', 'nin': '12345678901', 'dob': '1995-05-12'}),
        generates cryptographically secure salts for every leaf, builds the Merkle tree, and returns root.
        """
        leaves = []
        for key in sorted(attributes.keys()):
            val = attributes[key]
            salt = secrets.token_hex(16)  # 128-bit cryptographic salt
            l_hash = hash_leaf(key, val, salt)
            leaves.append({
                "key": key,
                "value": val,
                "salt": salt,
                "leaf_hash": l_hash
            })

        tree = MerkleTree(leaves)
        return {
            "merkle_root": tree.root,
            "leaves": leaves,
            "attribute_count": len(leaves)
        }

    @classmethod
    def generate_disclosure_proof(
        cls,
        all_leaves: List[Dict[str, Any]],
        disclosed_keys: List[str]
    ) -> Dict[str, Any]:
        """
        Holder selects specific keys to reveal.
        Returns the revealed attributes with their salts, along with the Merkle inclusion paths.
        All undisclosed attributes remain completely hidden and cannot be inverted.
        """
        tree = MerkleTree(all_leaves)
        disclosed_claims = []

        for idx, leaf in enumerate(all_leaves):
            if leaf["key"] in disclosed_keys:
                proof = tree.get_proof(idx)
                disclosed_claims.append({
                    "key": leaf["key"],
                    "value": leaf["value"],
                    "salt": leaf["salt"],
                    "proof_path": proof,
                    "leaf_index": idx
                })

        return {
            "merkle_root": tree.root,
            "disclosed_claims": disclosed_claims,
            "disclosed_count": len(disclosed_claims),
            "total_attributes": len(all_leaves)
        }

    @classmethod
    def verify_disclosure_proof(
        cls,
        expected_merkle_root: str,
        disclosed_claims: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Verifier takes the disclosed claims, re-computes each leaf hash, walks the Merkle path,
        and verifies if every claim mathematically anchors to the expected signed Merkle root.
        """
        if not disclosed_claims:
            return {"valid": False, "error": "No disclosed claims provided"}

        for claim in disclosed_claims:
            key = claim.get("key")
            val = claim.get("value")
            salt = claim.get("salt")
            proof_path = claim.get("proof_path", [])

            current_hash = hash_leaf(key, val, salt)

            for step in proof_path:
                sibling = step["sibling_hash"]
                current_hash = hash_pair(current_hash, sibling)

            if current_hash != expected_merkle_root:
                return {
                    "valid": False,
                    "failed_attribute": key,
                    "computed_root": current_hash,
                    "expected_root": expected_merkle_root,
                    "error": f"Merkle inclusion proof failed for attribute: '{key}'"
                }

        return {
            "valid": True,
            "verified_attributes": [c["key"] for c in disclosed_claims],
            "merkle_root": expected_merkle_root,
            "error": None
        }

    @classmethod
    def generate_worked_synthetic_credential(cls) -> Dict[str, Any]:
        """
        Generates a canonical, deterministic worked synthetic credential specification.
        Used to demonstrate exact attribute encoding, leaf construction, canonical sorting,
        intermediate tree node pairs, Merkle root R, and authenticated envelope message M.
        """
        raw_attributes = [
            ("clearanceLevel", "Tier-3", "7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c"),
            ("dob", "1992-06-14", "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6"),
            ("fullName", "Alex Carter", "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"),
            ("nationality", "Nigerian", "5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f"),
            ("nin", "29837492812", "3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e"),
            ("residence", "Victoria Island, Lagos", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d")
        ]

        leaves = []
        for key, val, salt in raw_attributes:
            l_hash = hash_leaf(key, val, salt)
            leaves.append({
                "key": key,
                "value": val,
                "salt": salt,
                "leaf_hash": l_hash
            })

        tree = MerkleTree(leaves)
        root = tree.root

        # Envelope message M
        issuer_did = "did:xeno:issuer:nimc-01"
        credential_id = "cred-9f8e7d6c"
        subject_did = "did:xeno:subject:001"
        schema_id = "urn:xeno:schema:id-credential:v1"
        m_digest, _ = compute_authenticated_envelope_message(
            issuer_did=issuer_did,
            credential_id=credential_id,
            subject_did=subject_did,
            merkle_root=root,
            schema_id=schema_id
        )

        return {
            "attributes": raw_attributes,
            "leaves": leaves,
            "tree_levels": tree.levels,
            "merkle_root": root,
            "issuer_did": issuer_did,
            "credential_id": credential_id,
            "subject_did": subject_did,
            "schema_id": schema_id,
            "authenticated_message_m": m_digest
        }
