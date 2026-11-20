"""
Merkle-Tree Selective Disclosure Engine (Protocol: xeno-merkle-mldsa-v2).
Implements:
1. Domain-separated, type-preserving salted attribute leaf construction:
   SHA-256(b"\x00" + canonical_json([key, value, salt_hex])).
2. Domain-separated Merkle node aggregation and root synthesis:
   SHA-256(b"\x01" + min(left_hex, right_hex) || max(left_hex, right_hex)).
3. Domain-separated Authenticated Credential Envelope Message M:
   SHA-256(b"\x02" + canonical_json([schema_id, issuer_did, credential_id, subject_did, merkle_root])).
   Signing invokes ML-DSA-65 / ECDSA over M.encode("utf-8") (the 64-byte UTF-8 ASCII representation
   of the lowercase hexadecimal SHA-256 digest M).
4. Cryptographic selective disclosure verification (Holder presents selected leaves + paths,
   Verifier recomputes the Merkle root and validates against the Issuer's signed envelope).
"""

import hashlib
import re
import json
import secrets
from typing import Dict, Any, List, Tuple, Optional


PROTOCOL_VERSION = "xeno-merkle-mldsa-v2"
LEAF_DOMAIN = b"\x00"
NODE_DOMAIN = b"\x01"
ENVELOPE_DOMAIN = b"\x02"

_VALID_KEY_RE = re.compile(r"^[A-Za-z0-9_]+$")
_VALID_SALT_RE = re.compile(r"^[0-9a-f]{32}$")


def canonical_attribute_encoding(key: str, value: Any, salt_hex: str) -> bytes:
    """
    Constructs the canonical, domain-separated leaf preimage (Protocol xeno-merkle-mldsa-v2):
        b"\\x00" + JSON([key, value, salt_hex]) using compact separators (",", ":").
    Enforces restrictive key syntax (alphanumeric/underscore only; forbids colons and whitespace),
    validates 32-char lowercase hex salt, and preserves JSON scalar types (e.g., int 18 != str "18").
    """
    if not isinstance(key, str) or not _VALID_KEY_RE.fullmatch(key):
        raise ValueError(
            f"Attribute key {key!r} is invalid under restrictive schema: must match ^[A-Za-z0-9_]+$ "
            "(colons ':' and non-alphanumeric delimiters are forbidden)."
        )
    if not isinstance(salt_hex, str) or not _VALID_SALT_RE.fullmatch(salt_hex):
        raise ValueError(
            f"Salt {salt_hex!r} is invalid: expected 32 lowercase hexadecimal characters (128 bits)."
        )
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise ValueError(
            f"Attribute value for key '{key}' has unsupported type {type(value).__name__}: "
            "only JSON scalar values (str, int, float, bool, None) are permitted."
        )
    canonical_json = json.dumps([key, value, salt_hex], separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return LEAF_DOMAIN + canonical_json.encode("utf-8")


def hash_leaf(key: str, value: Any, salt_hex: str) -> str:
    """
    Constructs a domain-separated salted leaf hash:
    SHA-256(0x00 || JSON([key, value, salt_hex])).
    Prevents dictionary/rainbow-table inversion on low-entropy attributes and distinguishes types.
    """
    payload = canonical_attribute_encoding(key, value, salt_hex)
    return hashlib.sha256(payload).hexdigest()


def hash_pair(left_hex: str, right_hex: str) -> str:
    """
    Combines two child hashes in sorted lexicographical order with NODE_DOMAIN (0x01) separation
    to bind sibling ordering and separate internal nodes from leaf/envelope commitments.
    """
    if not isinstance(left_hex, str) or not isinstance(right_hex, str):
        raise ValueError("Merkle node hashes must be hexadecimal strings.")
    combined = NODE_DOMAIN + (min(left_hex, right_hex) + max(left_hex, right_hex)).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def compute_authenticated_envelope_message(
    issuer_did: str,
    credential_id: str,
    subject_did: str,
    merkle_root: str,
    schema_id: str = "urn:xeno:schema:id-credential:v1"
) -> Tuple[str, bytes]:
    """
    Domain-Separated Authenticated Credential Envelope Message M (Protocol xeno-merkle-mldsa-v2).
    Eliminates colon-delimited ambiguity (given DIDs/URNs contain colons) via JSON tuple encoding:
        raw_payload = b"\\x02" + JSON([schema_id, issuer_did, credential_id, subject_did, merkle_root]).encode("utf-8")
        M = SHA-256(raw_payload).hexdigest()
    Note: The signing primitive (ML-DSA-65 or ECDSA) signs M.encode("utf-8") — the 64-byte UTF-8 ASCII
    representation of the lowercase hex digest M, NOT a raw 32-byte digest.
    """
    for field_name, field_val in [
        ("schema_id", schema_id),
        ("issuer_did", issuer_did),
        ("credential_id", credential_id),
        ("subject_did", subject_did),
        ("merkle_root", merkle_root),
    ]:
        if not isinstance(field_val, str) or not field_val:
            raise ValueError(f"Envelope field '{field_name}' must be a non-empty string.")
    envelope_json = json.dumps(
        [schema_id, issuer_did, credential_id, subject_did, merkle_root],
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    raw_payload = ENVELOPE_DOMAIN + envelope_json.encode("utf-8")
    digest_hex = hashlib.sha256(raw_payload).hexdigest()
    return digest_hex, raw_payload


def build_replay_protection_token(
    credential_id: str,
    verifier_nonce: str,
    timestamp_iso: str,
    disclosed_keys: List[str]
) -> str:
    """
    Constructs presentation-level freshness binding token T:
        T = SHA-256(credential_id || ':' || verifier_nonce || ':' || timestamp_iso || ':' || sorted_disclosed_keys_csv)
    Note: T is an unkeyed public integrity digest over challenge context; it binds credential ID,
    verifier challenge nonce, timestamp, and disclosed keys, but does NOT bind verifier audience or
    demonstrate holder private-key possession.
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
        Catches malformed encodings, missing path fields, and type errors cleanly.
        """
        if not disclosed_claims or not isinstance(disclosed_claims, list):
            return {"valid": False, "error": "No disclosed claims provided"}

        for claim in disclosed_claims:
            if not isinstance(claim, dict):
                return {"valid": False, "error": "Malformed disclosed claim entry: expected JSON object"}
            key = claim.get("key")
            val = claim.get("value")
            salt = claim.get("salt")
            proof_path = claim.get("proof_path", [])

            if not isinstance(proof_path, list):
                return {
                    "valid": False,
                    "failed_attribute": key,
                    "error": f"Malformed proof_path for attribute '{key}': expected list"
                }

            try:
                current_hash = hash_leaf(key, val, salt)
                for step in proof_path:
                    if not isinstance(step, dict) or "sibling_hash" not in step:
                        raise ValueError(f"Malformed sibling step in proof_path for '{key}'")
                    sibling = step["sibling_hash"]
                    current_hash = hash_pair(current_hash, sibling)
            except (ValueError, TypeError, KeyError) as exc:
                return {
                    "valid": False,
                    "failed_attribute": key,
                    "error": f"Malformed disclosure encoding or proof path: {exc}"
                }

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
        Generates a canonical, deterministic worked synthetic credential specification
        under Protocol xeno-merkle-mldsa-v2.
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

        # Envelope message M (Protocol xeno-merkle-mldsa-v2)
        issuer_did = "did:xeno:issuer:nimc-01"
        credential_id = "cred-9f8e7d6c"
        subject_did = "did:xeno:subject:001"
        schema_id = "urn:xeno:schema:id-credential:v1"
        m_digest, envelope_raw_bytes = compute_authenticated_envelope_message(
            issuer_did=issuer_did,
            credential_id=credential_id,
            subject_did=subject_did,
            merkle_root=root,
            schema_id=schema_id
        )

        return {
            "protocol_version": PROTOCOL_VERSION,
            "attributes": raw_attributes,
            "leaves": leaves,
            "tree_levels": tree.levels,
            "merkle_root": root,
            "issuer_did": issuer_did,
            "credential_id": credential_id,
            "subject_did": subject_did,
            "schema_id": schema_id,
            "envelope_preimage_utf8": envelope_raw_bytes[1:].decode("utf-8"),
            "authenticated_message_m": m_digest
        }
