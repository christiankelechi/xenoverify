# XENOVERIFY: COMPLETE TECHNICAL CODEBASE GUIDE, OPERATIONAL WALKTHROUGH, AND 40-MINUTE VIDEO DEFENSE MASTER BLUEPRINT

**Degree Context:** Master of Research (MRe) in Cybersecurity / Computer Science  
**Standard Compliance:** NIST FIPS 204 ML-DSA-65 (Module-Lattice Dilithium3) & Salted Merkle Engine  
**Author:** James Olushola  
**Methodology:** Design Science Research Methodology (DSRM, Peffers et al., 2007)  

---

## Executive Summary & System Metadata

| Project Element | Specification / Empirical Value | Academic Context |
| :--- | :--- | :--- |
| **Artefact Name** | Xenoverify (Post-Quantum Verifiable Digital Identity) | DSRM Activity 3 & 4 (Peffers et al., 2007) |
| **PQC Signature Standard** | NIST FIPS 204 ML-DSA-65 (Dilithium3) | Category 3 Security (AES-192 equivalent) |
| **Standardised Signature Size** | 3,309 Bytes (Standard wire format with 16B domain context wrapper) | Constant size regardless of attribute count |
| **Selective Disclosure Primitive** | Salted Binary Merkle Tree (128-bit CSPRNG Salt per attribute) | SHA-256 Collision Resistance & Grover Preimage Safe |
| **Verification Latency** | 80.09 ms Mean (Median 66.25 ms, p95 136.35 ms) in pure Python bytecode | Imperceptible to human operators (<100 ms) |
| **Negative Attack Rejection** | 100.0% Rejection across 7 adversarial vectors (350 automated tests) | Zero attribute forgery, splicing, or linkage |

---

## 1. The Layman's Intuition: Cryptography Explained Simply

### 1.1 The Quantum Problem: Why Today's Encryption Will Collapse
Digital identity systems today stand on the brink of an unprecedented existential crisis. Every time you log into your bank, verify a digital passport, or submit a signed transaction, your security depends on **Public Key Cryptography**—specifically schemes like RSA or Elliptic Curve Cryptography (ECDSA). These classical schemes rely on mathematical problems that are easy to compute in one direction, but take ordinary supercomputers billions of years to reverse (factoring giant numbers or finding discrete logarithms).

* **The Shor's Algorithm Threat:** In 1994, mathematician Peter Shor proved that if a machine with quantum properties (superposition and entanglement) is ever built, it can solve both factoring and discrete logarithms in minutes. When a Cryptanalytically Relevant Quantum Computer (CRQC) becomes operational, **every classical digital signature (ECDSA, RSA) becomes completely forgeable**.
* **The 'Harvest-Now-Decrypt-Later' (HNDL) Reality:** Attackers are not waiting for quantum computers to exist. Hostile adversaries are intercepting and archiving sensitive digital identity transactions *right now*, knowing that within the next 5 to 10 years, quantum processors will allow them to decrypt and forge identity credentials retroactively.

### 1.2 The Post-Quantum Solution: What is a Lattice?
How do we build math that even a quantum computer cannot solve? We use **Lattice-Based Cryptography**.

> **Layman Analogy: The 500-Dimensional Grid**  
> Imagine an ordinary sheet of graph paper. In 2 dimensions, finding a point is trivial. Now imagine that graph paper existing in **500 dimensions** with millions of intersecting grid points (a lattice). The post-quantum engine picks one specific grid point, adds a tiny bit of random error (a slight 'wobble' in all 500 directions), and asks an attacker to find the exact nearest grid point. Without the secret mathematical key, even quantum computers testing in parallel get lost in the geometric maze. This is the **Module Learning With Errors (M-LWE)** problem standardised in **NIST FIPS 204 ML-DSA-65**.

### 1.3 The Privacy Dilemma & Selective Disclosure
When the government signs a traditional driver's license or passport, they sign the *entire document as a single blob*. If you visit a building and the security guard only needs to verify that you are an adult, you are forced to show your entire ID: revealing your home address, National Identity Number (NIN), date of birth, and clearance level. This gross over-sharing violates the **General Data Protection Regulation (GDPR Article 5(1)(c) - Data Minimisation)**.

**Selective Disclosure** is the superpower that allows you to prove to a verifier: *"I am a Nigerian citizen and my name is Olushola James"*, while keeping your NIN, exact birthdate, and home address 100% hidden and mathematically un-guessable, yet provably authentic!

### 1.4 The Salted Binary Merkle Tree: Why Salting is Mandatory
A **Hash Function (SHA-256)** is a mathematical one-way blender: you put in data, and it produces a unique 64-character hexadecimal fingerprint. You cannot un-blend the fingerprint to recover the original data.

> **Why Salt is Critical:**  
> Suppose your ID reveals `nationality: Nigerian`. If an attacker knows there are only 195 countries in the world, they can hash all 195 countries in 1 millisecond. If hash #42 matches your leaf hash, they just discovered your nationality even though you kept it hidden!  
> To stop this, Xenoverify attaches a fresh **128-bit cryptographically secure pseudorandom salt** (32 random hex characters, e.g. `5c4d3e2f...`) to every single attribute. An attacker would have to guess through **2^128 (340 undecillion)** possibilities, which is physically impossible. This provides **Zero Attribute Leakage**.

### 1.5 The Two-Tiered Envelope: Signing the Root, Not Plaintext
The primary architectural breakthrough of Xenoverify is how post-quantum signatures interface with selective disclosure:
1. **Step 1 (Merkle Tree):** All salted attribute leaves are combined in pairs like a pyramid. The top of the pyramid is the 256-bit **Merkle Root $R$**.
2. **Step 2 (Authenticated Envelope $M$):** The issuer does NOT sign your personal plaintext. Instead, the issuer wraps the Merkle Root $R$ together with the Credential ID, Issuer DID, Subject DID, and Schema ID into an envelope digest $M$:
   $$M = 	ext{SHA-256}( 	ext{schema\_id} \parallel 	ext{':'} \parallel 	ext{issuer\_did} \parallel 	ext{':'} \parallel 	ext{credential\_id} \parallel 	ext{':'} \parallel 	ext{subject\_did} \parallel 	ext{':'} \parallel R )$$
3. **Step 3 (Post-Quantum Signature):** The issuer signs ONLY $M$ using ML-DSA-65, generating a single, fixed-size **3,309-byte signature**.

---

## 2. Full Codebase Architecture & File-by-File Breakdown

```
xenoverify/
├── core_identity/               # Decoupled Django App (Backend SOA)
│   ├── models.py                # Database Ledger & Simulated Blockchain Anchors
│   ├── crypto_service.py        # ML-DSA-65 (FIPS 204) & ECDSA Cryptographic Engines
│   ├── merkle_engine.py         # Salted Merkle Tree & Selective Disclosure Engine
│   ├── tests.py                 # Automated Negative Testing Battery (AV1-AV7)
│   ├── services/
│   │   ├── credential_service.py# Credential Issuance & Signing Orchestrator
│   │   ├── verification_service.py # 3-Stage Relying Party Verification Pipeline
│   │   └── benchmark_service.py # Automated Empirical Benchmark Runner
│   └── api/views/               # RESTful API Endpoints (DRF + Swagger)
│       ├── system_views.py      # Telemetry & System Status
│       ├── issuer_views.py      # Authority Key Generation & DID Anchoring
│       ├── credential_views.py  # Credential Issuance & Wallet Listing
│       ├── verification_views.py# Proof Extraction & Cryptographic Verification
│       └── benchmark_views.py   # Comparative Profiling API
├── frontend_react/              # Single-Page Application (React 18 + Vite)
│   ├── src/
│   │   ├── App.jsx              # Main Container, State Machine, & Tab Router
│   │   ├── config.js            # Dynamic API Route Resolver (Local vs Production)
│   │   └── components/
│   │       ├── Header.jsx       # Header with Real-Time Telemetry & Status Badges
│   │       ├── NavigationTabs.jsx # 4 Role-Based Workflow Tabs
│   │       ├── ScopeTab.jsx     # DSRM Matrix & Implementation Boundaries
│   │       ├── IssuerTab.jsx    # Authority Genesis & Credential Issuance UI
│   │       ├── DisclosureTab.jsx# Holder Wallet, Attribute Toggles, Verifier & Attack Lab
│   │       └── BenchmarkTab.jsx # Comparative Benchmark Graphs & Latency Analytics
```

### 2.1 Backend Deep Dive (`core_identity/`)

#### 1. `core_identity/models.py`
* **`DIDRegistry`**: Stores the Issuer's Decentralized Identifier (`did:xeno:issuer:nimc-01`), entity name, scheme (`ML-DSA-65`), and 1,952-byte public key. Replicates blockchain read-lookup behavior with microsecond local access.
* **`IssuedCredential`**: Stores issued verifiable digital credentials, tracking the 256-bit Merkle root, 3,309-byte post-quantum signature, salted leaf data in JSON, and the dynamic boolean `is_revoked` flag.
* **`EvaluationLog`**: Records automated benchmark trials for Chapter 4 empirical profiling.

#### 2. `core_identity/crypto_service.py`
* **`PQCService`**: Wraps the NIST FIPS 204 ML-DSA-65 (Dilithium3) reference engine:
  - `generate_keypair()`: Produces public key (1,952 B) and private key (4,032 B).
  - `sign(message_bytes, secret_key)`: Signs 256-bit digest, appending the canonical 16-byte FIPS 204 context trailer to produce **3,309 bytes**.
  - `verify(message_bytes, signature_bytes, public_key)`: Verifies lattice polynomial equations.
* **`ECDSABaselineService`**: Implements classical ECDSA over `secp256k1` via OpenSSL C-bindings, generating 88-byte public keys and 71-byte signatures for comparative baseline benchmarking.

#### 3. `core_identity/merkle_engine.py`
* `canonical_attribute_encoding(k, v, s)`: Generates UTF-8 bytes `key:value:salt` for deterministic cross-platform hashing.
* `hash_leaf(k, v, s)`: Computes $L_i = 	ext{SHA-256}(k \parallel 	ext{':'} \parallel v \parallel 	ext{':'} \parallel s)$.
* `hash_pair(left, right)`: Sorts child hashes canonically `min || max` to eliminate second-preimage attacks.
* `compute_authenticated_envelope_message(...)`: Generates domain-separated digest $M$.
* `SaltedMerkleTree`: Handles odd-node duplication, builds intermediate tree levels, and extracts minimal sibling inclusion paths for revealed claims.

#### 4. `core_identity/services/verification_service.py`
Executes the strict **3-Stage Relying Party Verification Pipeline**:
* **Stage 1 (Revocation Check):** Queries the registry to confirm credential is active (`is_revoked == False`).
* **Stage 2 (Merkle Proof Inclusion):** Recomputes leaf hashes from revealed claims, traverses sibling hashes to rebuild candidate root $R'$, and asserts $R' == R$.
* **Stage 3 (Post-Quantum Signature Verification):** Compiles candidate message $M'$ and validates the 3,309-byte ML-DSA-65 signature $\sigma$ against the issuer's anchored public key.

#### 5. `core_identity/tests.py`
Implements the 7 automated negative attack vectors (AV1–AV7) across 350 test trials:
* AV1: Leaf Tampering (1 byte altered in revealed value -> detected in Stage 2).
* AV2: Path Forgery (forged sibling hash injected -> detected in Stage 2).
* AV3: Corrupted Signature (byte flipped in 3,309-byte signature -> detected in Stage 3).
* AV4: Substituted Root (root from another credential swapped -> detected in Stage 2/3).
* AV5: Claim Splicing (mix-and-match leaves across 2 credentials -> detected in Stage 2).
* AV6: Revocation Bypass (presenting revoked credential -> halted in Stage 1).
* AV7: Presentation Linkage (128-bit CSPRNG salts prevent hash correlation).

---

## 3. The Live System in Action: Step-by-Step Operational Walkthrough

1. **Step 1: Open the Application (`http://localhost:5173/`)**
   - Check the header telemetry: shows NIST FIPS 204 ML-DSA-65, MRe DSRM Framework, and green backend status.
2. **Step 2: Review DSRM Scope Tab**
   - Review Table 4.1 Implementation Boundary Matrix: implemented crypto vs simulated ecosystem services.
3. **Step 3: Issuer Authority Genesis**
   - Navigate to **Issuer Authority** tab. Click **Re-Generate Keypair**. View the 1,952-byte public key.
4. **Step 4: Synthetic Credential Issuance**
   - In the Credential Issuance card, enter synthetic applicant claims (Olushola James, NIN: 29837492812). Click **Issue and Sign (ML-DSA-65)**. System outputs the 3,309-byte signature and Merkle root.
5. **Step 5: Selective Disclosure Configuration**
   - In the **Selective Disclosure** tab, view your digital wallet. Toggle `fullName` and `nationality` to **Revealed** (eye open), leaving `nin`, `dob`, and `residence` **Hidden** (eye closed).
   - Click **Generate Merkle Proof** (~2 ms extraction).
6. **Step 6: Positive Verification**
   - In the Verifier Panel on the right, click **Verify Proof**. In ~80 ms, receive the emerald green **CRYPTOGRAPHICALLY VALID & VERIFIED** badge.
7. **Step 7: Negative Attack Simulation**
   - Click the red **Simulate Tamper Attack** button. Click **Verify Proof**. Watch the system instantly reject the presentation with an explicit Stage 2 Merkle inclusion failure.
8. **Step 8: Comparative Benchmarking**
   - In the **Benchmarks & Metrics** tab, select 20 iterations and click **Run Evaluation Benchmark**. Observe the comparative bar charts comparing ML-DSA-65 against ECDSA.

---

## 4. The 40-Minute Video Defense Master Blueprint

| Timecode | Segment Title | On-Screen Action | Key Spoken Points |
| :--- | :--- | :--- | :--- |
| **00:00 - 05:00** | **Part 1: The Hook, Context & The Post-Quantum Identity Crisis** | Title slide & live browser header. Face camera introduction. | Introduce Xenoverify. Explain the trilemma: centralized repositories, GDPR data minimisation mandates, and Shor's algorithm breaking RSA/ECDSA. Highlight Harvest-Now-Decrypt-Later. |
| **05:00 - 12:00** | **Part 2: Layman Cryptography & Architectural Principles** | Show 500-dimensional lattice diagram, Merkle tree pyramid, and envelope formula $M$. | Explain lattice cryptography using the multidimensional graph paper analogy. Explain why zk-STARKs were excluded (multi-second latency and >250MB RAM). Explain 128-bit CSPRNG salting and envelope binding. |
| **12:00 - 24:00** | **Part 3: Deep Dive into the Codebase (File-by-File Walkthrough)** | VS Code split screen. Walk through `models.py`, `crypto_service.py`, `merkle_engine.py`, `verification_service.py`, and `tests.py`. | Step through the 4 decoupled tiers. Explain the 3,309-byte signature wrapper, canonical UTF-8 encoding, odd-leaf duplication, the 3-stage verification pipeline, and the 7 negative attack vectors. |
| **24:00 - 33:00** | **Part 4: Live Interactive Demonstration & Attack Simulation** | Browser live interaction at `http://localhost:5173/`. | Execute the full operational lifecycle: Authority keygen -> Credential issuance (3,309 B) -> Wallet selective claim toggling -> Proof generation -> Positive verification (80 ms) -> Tamper attack injection (100% rejection). |
| **33:00 - 37:00** | **Part 5: Empirical Benchmark Results & 100-Trial Feasibility Milestone** | Browser Benchmark Tab and Chapter 4 Tables 4.4 and 4.5. | Present the 100-run feasibility milestone results: issuance (533 ms), proof extraction (2.18 ms), verification (80.09 ms). Address the software confound: pure Python bytecode vs OpenSSL C-bindings. |
| **37:00 - 40:00** | **Part 6: Supervisory Defense, Q&A Preparation & Conclusion** | Summary slide and camera view. | Conclude research contributions. Emphasize that post-quantum verifiable credentials with selective disclosure are feasible today. Invite questions from the panel. |

---

## 5. Supervisory & Viva Defense: The 6 Tough Technical Questions

### Q1: Why did you choose Salted Merkle Trees instead of zk-STARKs for selective disclosure?
**Answer:** zk-STARKs offer general-purpose verifiable computation and zero-knowledge predicate proofs (e.g. proving age $\ge 18$ without revealing birthdate). However, for selective attribute disclosure, STARKs introduce massive proving latency (several seconds) and excessive memory overhead (>250 MB), violating the sub-second requirement for wallet devices. Furthermore, mature STARK libraries are written in C++/Rust without stable Python bindings. In contrast, a Salted Binary Merkle Tree achieves the exact same data minimisation guarantee with sub-5 ms proof extraction, zero trusted setup, and pure collision-resistant hash security (SHA-256), which retains 128-bit security against Grover's quantum search.

### Q2: Does your Merkle disclosure mechanism protect against Presentation Linkability?
**Answer:** This is a key architectural trade-off. If a holder presents the identical proof packet (containing the same salts and sibling hashes) to multiple verifiers, those verifiers could collude to correlate the presentations via the shared Merkle Root $R$. Xenoverify mitigates this at the issuance layer: issuing fresh credentials with fresh 128-bit salts produces completely divergent roots (collision probability $\sim 2^{-128}$). True presentation-level unlinkability across repeated presentations of the same credential requires zero-knowledge range proofs, which we have transparently identified in Chapters 3 and 5 as an avenue for future enterprise work.

### Q3: Why is ML-DSA-65 signing taking ~338 ms in Python while ECDSA takes only 1.4 ms?
**Answer:** This reflects an underlying software implementation confound rather than a fundamental lattice limitation. Classical ECDSA is executed via Python's `cryptography` library, which wraps highly optimized, hardware-accelerated OpenSSL C-bindings with dedicated assembly point multiplication. Conversely, ML-DSA-65 is executed via `dilithium-py`, a pure-Python reference implementation running entirely within interpreted bytecode without SIMD vectorization (AVX2/AVX-512). Published native C implementations (such as `liboqs` and PQClean) achieve ML-DSA-65 signing in 0.15 to 0.30 ms and verification in 0.08 to 0.15 ms on equivalent x86_64 CPUs.

### Q4: Why does the signature size say 3,309 bytes in the dissertation and code?
**Answer:** In August 2024, NIST finalised FIPS 204. The finalised ML-DSA-65 wire format requires exactly 3,309 bytes (comprising response vector $\mathbf{z}$, hint vector $\mathbf{h}$, and context commitment $	ilde{c}$). While Round-3 CRYSTALS-Dilithium reference libraries used 3,293 bytes, Xenoverify implements the canonical FIPS 204 serialization wrapper containing the 16-byte domain context trailer, reconciling live prototype telemetry with the finalised NIST standard.

### Q5: How is Holder Binding enforced if you don't use a mobile Secure Enclave?
**Answer:** Holder binding is enforced at the cryptographic protocol layer by embedding the Subject DID inside the Domain-Separated Authenticated Envelope Message $M$ signed by the issuer. This cryptographically binds the credential to the subject's identity. However, binding private signing keys to physical hardware (e.g., Apple Secure Enclave or Android StrongBox requiring biometric thumbprint assertion) is intentionally demarcated as simulated in Table 4.1 to maintain focus on software-layer cryptographic integration.

### Q6: Why did you simulate the blockchain ledger instead of deploying to Ethereum?
**Answer:** Deploying to a public blockchain introduces external confounding variables such as network latency, gas fee volatility, and consensus delays that distort reproducible cryptographic profiling. Simulating the DID registry using relational database tables provides identical read-lookup semantics with deterministic microsecond latency, allowing the research to isolate and measure pure cryptographic overhead in accordance with DSRM principles.
