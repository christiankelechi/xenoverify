# Xenoverify: Post-Quantum Digital Identity Verification Prototype

Prototype implementing Post-Quantum Digital Identity Verification with Selective Disclosure, designed specifically to satisfy **MRe Thesis requirements under the Design Science Research Methodology (DSRM)** (Peffers et al., 2007).

---

## 1. System Architecture & Standards

- **Primary Signature Scheme:** **NIST FIPS 204 ML-DSA-65** (Module-Lattice-Based Digital Signature Algorithm - Dilithium3).
  - Public Key: **1,952 bytes**
  - Private Key: **4,032 bytes**
  - Signature: **3,309 bytes** (NIST FIPS 204 canonical wire format)
  - Security Category: NIST Level 3 (Quantum Resistant)
- **Comparative Baseline Scheme:** **ECDSA over secp256k1** (Classical 128-bit baseline for Chapter 4 trade-off evaluation).
- **Selective Disclosure Mechanism:** **Salted Merkle Tree Commitments**.
  - Leaf construction: $H(\text{attribute} \parallel \text{value} \parallel \text{salt})$ with 128-bit CSPRNG salt.
  - Generates verifiable audit paths without leaking undisclosed attributes.
- **Backend:** Python 3.11 + Django 5 + Django REST Framework.
- **Frontend:** React 18 + Vite + Modern Glassmorphism UI.

---

## 2. Table 3.1 Scope Compliance (Dissertation Ground Truth)

| Component | Scope | Evaluation Treatment |
| :--- | :--- | :--- |
| **Post-quantum signing** | **Implemented** | Functional, security and performance testing (ML-DSA-65) |
| **Selective disclosure/proof** | **Implemented** | Proof generation, verification, security and performance testing |
| **Core identity-verification workflow** | **Implemented** | Integrated workflow testing and measurement |
| **Wallet** | **Simulated** | Workflow representation only; not treated as a production wallet |
| **Ledger/blockchain** | **Simulated** | Integrity/anchoring behaviour represented for evaluation |
| **Revocation** | **Simulated** | Workflow and trade-off analysis; not a production revocation service |

---

## 3. How to Run Locally

### Terminal 1: Django REST Backend
```bash
# Navigate to the workspace root
cd xenoverify

# Run migrations (already applied)
python manage.py migrate

# Start the Django server on port 8000
python manage.py runserver 8000
```
Backend API will be accessible at: `http://localhost:8000/api/`

### Terminal 2: React Frontend
```bash
# Navigate to the frontend directory
cd xenoverify/frontend_react

# Launch the development server
npm run dev
```
Frontend Web Dashboard will be accessible at: `http://localhost:5173/`

---

## 4. Endpoints Quick Reference

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/api/system/info/` | `GET` | Returns cryptographic parameters, library versions & Table 3.1 mapping |
| `/api/issuers/initialize/` | `POST` | Generates ML-DSA-65 Issuer DID and keypair |
| `/api/credentials/issue/` | `POST` | Salts leaves, creates Merkle root, and signs with ML-DSA-65 |
| `/api/credentials/list/` | `GET` | Lists issued credentials for simulated holder wallet |
| `/api/proofs/generate/` | `POST` | Extracts Merkle selective disclosure inclusion paths |
| `/api/proofs/verify/` | `POST` | Verifier cryptographically checks signature + Merkle paths |
| `/api/benchmarks/run/` | `POST` | Automated benchmark suite generating Chapter 4 evaluation tables |

---

## 5. Prototype Demonstration & Verification Points

1. **Demonstrate Feasibility:** Navigate to the **"Issuer Authority"** tab and issue a credential signed with ML-DSA-65.
2. **Demonstrate Selective Disclosure:** Open the **"Selective Disclosure Playground"**, toggle between disclosing "Name" and "Nationality" while keeping "NIN" and "Date of Birth" hidden. Click **"Verify Proof"** to see instant positive verification (~50ms).
3. **Demonstrate Tamper Resistance (Negative Testing):** Click **"Simulate Tamper Attack"**; the verifier immediately rejects the altered payload with an explicit Merkle integrity violation.
4. **Generate Chapter 4 Data:** Open the **"Benchmarks & Metrics"** tab, run 20 or 50 trials, and copy the calculated Mean, Median, and $p_{95}$ tail latencies directly into Chapter 4.
