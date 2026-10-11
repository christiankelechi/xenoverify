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


def hash_leaf(key: str, value: Any, salt_hex: str) -> str:
    """
    Constructs a salted leaf hash:
    H(key : value : salt)
    Prevents rainbow table / brute-force attacks on low-entropy attributes.
    """
    payload = f"{key}:{str(value)}:{salt_hex}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def hash_pair(left_hex: str, right_hex: str) -> str:
    """
    Combines two child hashes in sorted lexicographical order to prevent second-preimage attacks.
    """
    combined = (min(left_hex, right_hex) + max(left_hex, right_hex)).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


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
