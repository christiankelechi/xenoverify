"""
Django Models representing the Simulated DSRM Ecosystem:
- Simulated DID Registry (Decentralized Identifier Anchors)
- Issued Digital Credentials with Merkle Commitments & PQC Signatures
- Simulated Revocation Registry
- Experimental Audit & Evaluation Logs (for Chapter 4 metrics)
"""

from django.db import models
import uuid


class DIDRegistry(models.Model):
    """
    Simulated Blockchain / Ledger DID Registry.
    Anchors the Issuer's Decentralized Identifier and Public Keys.
    """
    did = models.CharField(max_length=128, primary_key=True)
    entity_name = models.CharField(max_length=255, default="National Identity Management Commission (NIMC Simulator)")
    scheme = models.CharField(max_length=64, default="ML-DSA-65 (NIST FIPS 204)")
    public_key_b64 = models.TextField()
    public_key_bytes = models.IntegerField(default=1952)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.entity_name} ({self.did})"


class IssuedCredential(models.Model):
    """
    Represents an issued Verifiable Digital Credential.
    Encapsulates Salted Merkle Root commitment and Post-Quantum / Classical signature,
    along with the Authenticated Credential Envelope message M.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subject_did = models.CharField(max_length=128)
    issuer = models.ForeignKey(DIDRegistry, on_delete=models.CASCADE, related_name="issued_credentials")
    schema_id = models.CharField(max_length=128, default="urn:xeno:schema:id-credential:v1")
    merkle_root = models.CharField(max_length=64, db_index=True)
    envelope_message = models.CharField(max_length=64, blank=True, null=True, help_text="Authenticated Credential Envelope digest M")
    signature_scheme = models.CharField(max_length=64, default="ML-DSA-65")
    signature_b64 = models.TextField()
    signature_bytes = models.IntegerField(default=3309)
    attributes_json = models.JSONField(help_text="Stores full attribute mapping")
    leaves_json = models.JSONField(help_text="Stores salted leaf details for wallet simulation")
    attribute_count = models.IntegerField(default=0)
    is_revoked = models.BooleanField(default=False)
    revocation_reason = models.CharField(max_length=255, blank=True, null=True)
    issued_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Cred {self.id} for {self.subject_did} (Root: {self.merkle_root[:8]}...)"


class VerifierNonce(models.Model):
    """
    Simulated Verifier Nonce Store for Presentation Replay Attack Defense.
    Nonces are bound to challenge-response sessions with 300-second TTL.
    Once verified, a nonce is marked consumed to prevent eavesdropped presentations.
    """
    nonce = models.CharField(max_length=128, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_consumed = models.BooleanField(default=False)
    consumed_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"Nonce {self.nonce} (consumed={self.is_consumed})"


class EvaluationLog(models.Model):
    """
    Stores metrics for Chapter 4 DSRM Evaluation & Benchmarking:
    - Scheme (ML-DSA-65 vs ECDSA)
    - Keygen latency, Signing latency, Verification latency
    - Key size, Signature size, Proof size
    - Disclosed attributes ratio
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    experiment_id = models.CharField(max_length=64, db_index=True)
    scheme = models.CharField(max_length=64)
    operation = models.CharField(max_length=64)  # keygen, sign, verify, full_workflow
    latency_ms = models.FloatField()
    payload_bytes = models.IntegerField(default=0)
    attribute_count = models.IntegerField(default=0)
    disclosed_count = models.IntegerField(default=0)
    success = models.BooleanField(default=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.scheme} - {self.operation}: {self.latency_ms}ms"
