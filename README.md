# OLYMPUS: Decentralized Identity Framework for Autonomous Metaverse Agents

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![IEEE TIFS](https://img.shields.io/badge/venue-IEEE%20TIFS-orange.svg)](#citation)

> **OLYMPUS** is a decentralized identity framework that extends W3C DID Core and
> Verifiable Credentials Data Model 2.0 with agent-specific identity management,
> graduated autonomy enforcement, cryptographic delegation chains, and forensic
> accountability for autonomous AI agents operating across metaverse environments.

---

## Table of Contents

- [Overview](#overview)
- [Key Contributions](#key-contributions)
- [Architecture](#architecture)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Module Reference](#module-reference)
  - [Core Types (`olympus.core`)](#core-types)
  - [Cryptographic Primitives (`olympus.crypto`)](#cryptographic-primitives)
  - [DID Layer (`olympus.did`)](#did-layer)
  - [Verifiable Credentials (`olympus.vc`)](#verifiable-credentials)
  - [Agent Identity (`olympus.agent`)](#agent-identity)
  - [Protocol Suite (`olympus.protocol`)](#protocol-suite)
  - [Forensic Audit (`olympus.forensics`)](#forensic-audit)
  - [Evaluation Suite (`olympus.evaluation`)](#evaluation-suite)
- [Running the Evaluation](#running-the-evaluation)
- [Security Properties](#security-properties)
- [Performance Summary](#performance-summary)
- [Formal Definitions](#formal-definitions)
- [Limitations](#limitations)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

## Overview

Autonomous AI agents operating across metaverse platforms pose identity
challenges that no existing decentralized framework addresses:
authenticating non-human entities, enforcing bounded autonomy, and tracing
every agent action to a human principal. Existing systems—Sovrin, PolygonID,
Veramo, ION—implement W3C DID Core and Verifiable Credentials but universally
assume that each DID is controlled by a human being.

OLYMPUS resolves this gap by introducing:

- A **Quaternary World Model** (`W = {H, P, D, C}`) that distinguishes Human,
  Physical, Digital, and Creative (autonomous agent) entities as
  cryptographically distinct identity classes.
- **Five cryptographic protocols** governing the complete agent identity
  lifecycle with formal security guarantees.
- **Graduated autonomy levels** (AL-0 through AL-4) attested via signed
  credentials, not self-reported.
- A **forensic accountability invariant** ensuring every agent action is
  traceable to a unique human principal under standard cryptographic assumptions.

---

## Key Contributions

| ID | Contribution | Description |
|----|-------------|-------------|
| **C1** | Quaternary World Model | Extension of Wang et al. (2023) ternary taxonomy with Creative World; formalisation of identity-binding function `β : W × W → {0,1}` |
| **C2** | Five Cryptographic Protocols | AGP, CMAP, PPAP, CPP, AAP with formal proofs under EUF-CMA (Ed25519) and HVZK in ROM (Schnorr–Fiat–Shamir) |
| **C3** | DID-Based Agent Identity | W3C-compliant `did:olympus` method with type-specific documents, five attested autonomy levels, and capability ceilings |
| **C4** | Forensic Accountability | Cryptographic traceability to human principal via signed delegation chains and biometric-verified human override |
| **C5** | Comprehensive Evaluation | Sub-millisecond latency, 30/30 security tests passing, 12/14 attack vectors fully mitigated, 3,547-line open-source implementation |

---

## Architecture

OLYMPUS maps onto a six-layer security architecture adapted from the
ISA/IEC 62443 Purdue Reference Architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│  L5  Enterprise / Governance    Forensic Audit Trail            │
├─────────────────────────────────────────────────────────────────┤
│  L4  Business Logic             Autonomy Management, Delegation │
├─────────────────────────────────────────────────────────────────┤
│  L3  Operations                 AGP · CMAP · PPAP · CPP · AAP  │
├─────────────────────────────────────────────────────────────────┤
│  L2  Supervisory Control        DID CRUD, VC Issuance/Verify    │
├─────────────────────────────────────────────────────────────────┤
│  L1  Basic Control              Key Generation, Enclave Storage │
├─────────────────────────────────────────────────────────────────┤
│  L0  Physical Process           Biometric Sensors, TEE/HSM      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
olympus/
├── core/                       # Core type definitions
│   ├── __init__.py
│   └── types.py                # Quaternary World Model, autonomy levels,
│                               # agent types, capabilities, binding matrix β
├── crypto/                     # Cryptographic primitives
│   ├── __init__.py
│   └── primitives.py           # Ed25519, secp256k1, BLS12-381, SHA-256,
│                               # Schnorr proofs, Merkle trees, commitments,
│                               # HD key derivation, Base58 encoding
├── did/                        # Decentralized Identifier layer
│   ├── __init__.py
│   ├── document.py             # W3C DID Document with OLYMPUS extensions
│   └── method.py               # did:olympus CRUD operations and VDR
│
├── vc/                         # Verifiable Credentials layer
│   ├── __init__.py
│   ├── credential.py           # W3C VC Data Model 2.0, issuance, verification
│   └── presentation.py         # Verifiable Presentations with domain binding
│
├── agent/                      # Agent identity framework
│   ├── __init__.py
│   ├── identity.py             # Agent lifecycle, biometric binding,
│   │                           # delegation chains, emergency stop
│   └── autonomy.py             # Graduated autonomy enforcement (AL-0–AL-4)
│
├── protocol/                   # Five cryptographic protocols
│   ├── __init__.py
│   ├── agp.py                  # Avatar Genesis Protocol
│   ├── cmap.py                 # Cross-Metaverse Authentication Protocol
│   ├── ppap.py                 # Privacy-Preserving Attribute Proof Protocol
│   ├── cpp.py                  # Credential Portability Protocol
│   └── aap.py                  # Agent Authentication Protocol
│
├── forensics/                  # Forensic accountability
│   ├── __init__.py
│   └── audit.py                # Hash-chained, Ed25519-signed audit trail
│
├── evaluation/                 # Evaluation and benchmarking
│   ├── __init__.py
│   └── benchmarks.py           # Full evaluation suite for IEEE TIFS
│
├── run_all.py                  # Integration test + evaluation entry point
├── setup.py                    # Package configuration
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

**Codebase statistics:** 15 modules, 3,547 lines of Python 3.10+.

---

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | ≥ 3.10 | Type hints, `match` statements |
| `cryptography` | ≥ 41.0.0 | Ed25519 (OpenSSL backend) |
| `ecdsa` | ≥ 0.18.0 | secp256k1 ECDSA (RFC 6979) |
| `py_ecc` | ≥ 7.0.0 | BLS12-381 pairing arithmetic |
| `tabulate` | ≥ 0.9.0 | Evaluation result formatting |

---

## Installation

### From Source

```bash
git clone https://github.com/blockchainlab/olympus-identity.git
cd olympus-identity
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or install as a development package:

```bash
pip install -e .
```

### Verify Installation

```bash
python -c "from olympus.core.types import WorldType; print(WorldType.CREATIVE.value)"
# Expected output: creative
```

---

## Quick Start

### Minimal Example: Human → Agent → Authenticate → Audit

```python
from olympus.core.types import *
from olympus.crypto.primitives import Ed25519KeyGenerator
from olympus.did.method import OlympusDIDMethod
from olympus.agent.identity import AgentIdentityManager
from olympus.protocol.agp import AvatarGenesisProtocol
from olympus.protocol.aap import (
    AgentAuthenticationProtocol, DelegationVerifier, DelegationLink
)
from olympus.forensics.audit import ForensicAuditTrail, ActionType

gen = Ed25519KeyGenerator()

# 1. Create human DID
method = OlympusDIDMethod()
human_doc, human_kp = method.create(DIDType.HUMAN)

# 2. Avatar genesis via AGP
agp = AvatarGenesisProtocol()
session = agp.initiate(human_doc.id)
sig = gen.sign(human_kp.private_key, session.challenge_nonce.encode())
result = agp.complete(session.session_id, sig, human_kp.public_key)
assert result.state.value == "completed"

# 3. Create agent with biometric binding
mgr = AgentIdentityManager()
bio = b"simulated_facial_biometric"
tmpl = mgr.biometric.enroll(human_doc.id, bio)
binding = mgr.biometric.create_binding(human_doc.id, tmpl.template_id)
agent = mgr.create_agent(
    AgentType.AI, human_doc.id,
    name="ResearchAgent", biometric_binding_id=binding.binding_id
)

# 4. Authenticate agent via AAP
dv = DelegationVerifier()
payload = f"{human_doc.id}|{agent.did}|{agent.autonomy_level.value}".encode()
del_sig = gen.sign(human_kp.private_key, payload)
dv.register(DelegationLink(
    delegator_did=human_doc.id, delegate_did=agent.did,
    autonomy_level=agent.autonomy_level,
    capabilities=[AgentCapability.INTERACT, AgentCapability.RESPOND],
    signature=del_sig, delegator_public_key=human_kp.public_key,
))

aap = AgentAuthenticationProtocol(dv)
aap_session = aap.request_auth(
    agent.did, AgentType.AI, "interact", [AgentCapability.INTERACT]
)
agent_sig = gen.sign(agent.key_pair.private_key, aap_session.challenge.encode())
auth = aap.submit_proof(
    aap_session.session_id,
    agent_signature=agent_sig,
    agent_public_key=agent.key_pair.public_key,
    autonomy_vc_level=agent.autonomy_level,
)
assert auth.success

# 5. Forensic audit trail
audit_key = gen.generate()
trail = ForensicAuditTrail(signing_key=audit_key)
trail.log(human_doc.id, ActionType.IDENTITY_CREATE, human_doc.id,
          chain=[human_doc.id])
trail.log(agent.did, ActionType.AUTH_SUCCESS, "metaverse-alpha",
          chain=[human_doc.id, agent.did])
ok, _ = trail.verify_integrity()
assert ok

print(f"Human DID:  {human_doc.id}")
print(f"Avatar DID: {result.avatar_did}")
print(f"Agent DID:  {agent.did} (AL-{agent.autonomy_level.value})")
print(f"Auth token: {auth.session_token[:24]}...")
print(f"Audit log:  {len(trail.events)} events, integrity verified")
```

---

## Module Reference

### Core Types

**Module:** `olympus.core.types`

Defines the canonical type system for the OLYMPUS architecture.

| Type | Description |
|------|-------------|
| `WorldType` | Quaternary World Model: `HUMAN`, `PHYSICAL`, `DIGITAL`, `CREATIVE` |
| `DIDType` | DID classification: `HUMAN`, `DEVICE`, `AVATAR`, `AGENT` |
| `AutonomyLevel` | Graduated levels AL-0 (fully human-controlled) through AL-4 (fully autonomous) |
| `AgentType` | Agent classification: `NPC`, `AI`, `AUTONOMOUS`, `SERVICE` |
| `AgentCapability` | 14 capabilities across 4 risk tiers (Low, Medium, High, Critical) |
| `LayerType` | Purdue security layers L0–L5 |
| `SecurityBoundary` | TEE hardware, consensus, identity validation, cryptographic proof, protocol verification, application firewall |
| `VALID_BINDINGS` | Identity-binding matrix `β(source, target)` with 6 valid directed bindings |

**Autonomy level properties:**

| Level | Unsupervised Actions | Human Approval | Delegation Rule |
|-------|---------------------|----------------|-----------------|
| AL-0 | 0 | Required | — |
| AL-1 | 1 | Required | Can delegate to AL-0 |
| AL-2 | 10 | Not required | Can delegate to AL-0, AL-1 |
| AL-3 | 100 | Not required | Can delegate to AL-0–AL-2 |
| AL-4 | Unbounded | Not required | Can delegate to AL-0–AL-3 |

**Agent type ceilings:**

| Agent Type | Default AL | Maximum AL |
|------------|-----------|------------|
| NPC | AL-1 | AL-2 |
| AI | AL-2 | AL-3 |
| Autonomous | AL-3 | AL-4 |
| Service | AL-4 | AL-4 |

### Cryptographic Primitives

**Module:** `olympus.crypto.primitives`

Production-grade implementations with three signature backends:

| Primitive | Backend | Security Level | Performance |
|-----------|---------|---------------|-------------|
| Ed25519 (RFC 8032) | `cryptography` 41.x (OpenSSL) | ~128-bit | Sign: 0.077 ms |
| secp256k1 (ECDSA) | `ecdsa` 0.18.x (RFC 6979) | ~128-bit | Sign: 1.159 ms |
| BLS12-381 | `py_ecc` 7.x (pure Python) | ~128-bit | Sign: 156.3 ms |

**Additional primitives:**

| Primitive | Description | Use Case |
|-----------|-------------|----------|
| `SHA-256` | Collision-resistant hash (OpenSSL) | Credential digests, commitments |
| `SchnorrProof` | Fiat–Shamir sigma-protocol (ROM) | PPAP zero-knowledge attribute proofs |
| `Commitment` | `C = H(v ‖ r)`, computationally binding | PPAP attribute commitments |
| `MerkleTree` | Binary SHA-256 tree | Selective disclosure, audit batching |
| `HDKeyDerivation` | BIP-32 adapted for OLYMPUS | Hierarchical identity key management |
| `base58_encode` | Bitcoin-style Base58 | Multibase public key encoding |

### DID Layer

**Module:** `olympus.did.document`, `olympus.did.method`

Implements W3C DID Core v1.0 with OLYMPUS namespace extensions.

**DID method syntax:**
```
did:olympus:<type>:<id>
did:olympus:human:a1b2c3d4...
did:olympus:avatar:e5f6a7b8...
did:olympus:agent:ai:c9d0e1f2...
```

**OLYMPUS DID Document extensions** (under `olympus` namespace):

| Extension | Type | Description |
|-----------|------|-------------|
| `agentType` | string | `npc`, `ai`, `autonomous`, `service` |
| `autonomyLevel` | integer | 0–4 (attested, not self-reported) |
| `capabilities` | string[] | Granted capabilities from 14-type taxonomy |
| `delegationChain` | string[] | Authority path to human root |
| `worldBindings` | object | Materialisation of binding function β |

**CRUD lifecycle:**
- `create(did_type, ...)` → `(DIDDocument, KeyPair)`
- `resolve(did)` → `DIDResolutionResult`
- `update(did, updater)` → `DIDResolutionResult`
- `deactivate(did)` → `bool`

### Verifiable Credentials

**Module:** `olympus.vc.credential`, `olympus.vc.presentation`

W3C VC Data Model 2.0 issuance and verification with Ed25519 signatures.

**OLYMPUS-specific credential types:**

| Credential | Purpose | Binding |
|------------|---------|---------|
| `AvatarGenesisCredential` | Binds avatar DID to human creator | `SHA-256(DID_H)` + AGP signature |
| `AutonomyAttestationCredential` | Records attested autonomy level | Issued by delegating authority |
| `DelegationCredential` | Encodes signed delegation link | Delegator DID, capabilities, max AL |

**Verifiable Presentations** support domain-bound holder signatures with
challenge–response replay protection and selective disclosure integration
with PPAP.

### Agent Identity

**Module:** `olympus.agent.identity`, `olympus.agent.autonomy`

Agent lifecycle management with the accountability invariant:

```
∀ agent action a : ∃ human h, biometric proof p :
    Trace(a) → h  ∧  BioVerify(h, p) = true
```

**Key components:**

| Component | Description |
|-----------|-------------|
| `AgentIdentityManager` | Central lifecycle manager: create, delegate, authorise, emergency stop |
| `BiometricVerifier` | ISO/IEC 24745 template protection: `t = SHA-256(features)`, constant-time comparison |
| `DelegationRecord` | Signed delegation with capabilities, max AL, Ed25519 signature |
| `DelegationChain` | Immutable snapshot of authority path to human principal |
| `AutonomyManager` | Boundary enforcement, action approval pipeline, daily limits |

**Biometric binding operations requiring proof:**
1. Emergency stop of agent cascade
2. Authorisation of High- or Critical-risk capabilities
3. Delegation-chain root verification during forensic audit

### Protocol Suite

**Module:** `olympus.protocol.*`

Five cryptographic protocols governing the agent identity lifecycle:

#### AGP — Avatar Genesis Protocol (`protocol.agp`)

Binds a new avatar DID to its human creator via challenge–response.

| Property | Value |
|----------|-------|
| Rounds | 4 (initiate → challenge → sign → bind) |
| Challenge | 256-bit CSPRNG nonce |
| TTL | 300 s |
| Signature | Ed25519 over nonce |
| Avatar limit | 10 per human |
| Latency | 0.259 ms |
| Security | Binding integrity under EUF-CMA |

#### CMAP — Cross-Metaverse Authentication Protocol (`protocol.cmap`)

Authenticates identity transitions between platforms without a central provider.

| Property | Value |
|----------|-------|
| Payload | `SHA-256(DID) ‖ challenge ‖ domain` |
| TTL | 120 s |
| Isolation | Domain-bound signature prevents cross-platform reuse |
| Privacy | Human DID not disclosed; only holder-selected attributes |
| Latency | 0.246 ms |
| Security | Cross-domain isolation (Theorem 7) |

#### PPAP — Privacy-Preserving Attribute Proof Protocol (`protocol.ppap`)

Zero-knowledge predicate proofs using Schnorr sigma-protocol with Fiat–Shamir
non-interactive transformation.

| Property | Value |
|----------|-------|
| Proof types | Predicate (comparison), set membership, range, selective disclosure |
| Commitment | `C = SHA-256(v ‖ r)`, `r ←$ {0,1}^256` |
| Soundness | `2^{-256}` (hash output length) |
| ZK model | Honest-verifier ZK in Random Oracle Model |
| Prove | 0.033 ms per predicate |
| Verify | 0.005 ms per predicate |
| Proof size | 236 bytes per predicate |
| vs. Groth16 | 3,600× faster (prove), 700× faster (verify) |

#### CPP — Credential Portability Protocol (`protocol.cpp`)

Cross-chain credential transfer with schema translation and re-anchoring.

| Property | Value |
|----------|-------|
| Pipeline | Sign → Verify → Translate → Re-anchor |
| Export proof | Ed25519 signature over `SHA-256(credential)` |
| Schema mapping | Configurable field-name translation |
| Batching | Merkle-root amortisation (1,000 events = cost of 100) |
| Latency | 0.318 ms |

#### AAP — Agent Authentication Protocol (`protocol.aap`)

Authenticates autonomous agents with attested autonomy enforcement and
delegation-chain accountability.

| Property | Value |
|----------|-------|
| Auth predicate | `VerifySig(DID_A) ∧ action ∈ Caps(A) ∧ AL_attested permits action ∧ ValidDeleg(A → h)` |
| Challenge TTL | 60 s |
| Chain verification | Ed25519 verify per link, walk to `did:olympus:human:*` root |
| Human gate | Mandatory for AL ≤ 1 |
| Emergency override | Biometric-verified, cascading sub-agent deactivation |
| Latency | 0.375 ms |
| Security | Accountability (Theorem 3), non-escalation (Theorem 4) |

### Forensic Audit

**Module:** `olympus.forensics.audit`

Tamper-evident, append-only audit log with Merkle-chain integrity.

**Integrity mechanism:**
```
h_i = SHA-256(event_i ‖ h_{i-1}),  h_0 = 0^256
σ_i = Sign_Ed25519(sk, h_i)
```

| Property | Value |
|----------|-------|
| Tamper detection | Probability ≥ `1 − 2^{-256}` |
| Verification cost | `0.135 ms/event` (linear, `R² = 0.9999`) |
| Storage | 620 bytes per event |
| Event types | 16 (identity, auth, delegation, credential, agent, ZK proof operations) |
| Severity levels | 6 (INFO through EMERGENCY) |
| Query methods | By actor DID, action type, severity, human principal trace |

### Evaluation Suite

**Module:** `olympus.evaluation.benchmarks`

Comprehensive evaluation producing results for all paper tables and figures.

**Benchmark categories:**
1. Cryptographic primitive performance (Ed25519, secp256k1, BLS12-381, SHA-256, Schnorr, Merkle)
2. Protocol execution latency with per-phase breakdown
3. Delegation chain scalability (depth 1–10, regression analysis)
4. Concurrent agent scalability (100–100,000 agents)
5. Audit trail verification scalability (100–10,000 events)
6. Security property verification (30 tests)
7. Comparative analysis against 7 existing systems
8. ZK proof performance vs. predicate count

---

## Running the Evaluation

### Full Integration Test + Evaluation

```bash
python run_all.py
```

This executes:
1. **Integration test** — end-to-end scenario: Human → Avatar → Agent →
   Authenticate → Cross-Metaverse → ZK Proof → Credential Port → Audit → Emergency Stop
2. **Full evaluation suite** — all 8 benchmark categories (n=50 iterations per benchmark)
3. **Results export** — writes `evaluation_results.json`

### Expected Output

```
========================================================================
  OLYMPUS Integration Test
========================================================================

✓ Human DID created: did:olympus:human:...
✓ Avatar created via AGP: did:olympus:avatar:...
✓ VC issued and verified: urn:uuid:...
✓ Agent created: did:olympus:agent:ai:... (AL-2)
✓ Agent authenticated via AAP (token: aap_...)
✓ Cross-metaverse auth via CMAP (session: cmap_...)
✓ ZK attribute proof via PPAP: verified=[age, reputation], revealed={country: US}
✓ Credential exported and imported via CPP
✓ Audit trail: 4 events, integrity verified
✓ Emergency stop executed with biometric verification

========================================================================
  ALL INTEGRATION TESTS PASSED ✓
========================================================================
```

### Run Individual Benchmarks

```python
from olympus.evaluation.benchmarks import run_full_evaluation, print_results

# Run with custom iteration count
results = run_full_evaluation(bench_n=100)
print_results(results)
```

---

## Security Properties

OLYMPUS satisfies 30 security properties verified with `n = 1,000` trial
iterations each, grouped into four categories:

### Authentication Integrity

| ID | Property | Formal Basis |
|----|----------|-------------|
| S-1–S-5 | Ed25519 / secp256k1 EUF-CMA | RFC 8032, 0/5,000 false accepts |
| S-6, S-7 | AGP replay resistance | Nonce freshness + session state machine |
| S-8 | Binding integrity | Signature over `(DID ‖ nonce ‖ timestamp)` |
| S-9, S-10 | CMAP cross-domain isolation | Domain-bound challenge–response |
| S-11 | Session token entropy | 256-bit CSPRNG |

### Zero-Knowledge Guarantees

| ID | Property | Formal Basis |
|----|----------|-------------|
| S-12 | PPAP predicate soundness | Schnorr sigma-protocol, error `2^{-256}` |
| S-13 | HVZK in ROM | Fiat–Shamir simulator construction |
| S-14 | Proof unlinkability | Per-session nonce + fresh commitment |

### Delegation Governance

| ID | Property | Formal Basis |
|----|----------|-------------|
| S-17, S-18 | Delegation non-circumvention | Signed chain with per-link PK verification |
| S-19 | Autonomy ceiling enforcement | Attested AL vs. `type.max_autonomy` |
| S-20, S-21 | Human override guarantee | Protocol-level gate at AL ≤ 1 |

### Forensic Assurance

| ID | Property | Formal Basis |
|----|----------|-------------|
| S-22–S-24 | Audit tamper evidence | Hash chain + per-event Ed25519 signature |
| S-25–S-28 | Accountability completeness | Biometric binding + delegation chain |
| S-30 | Nonce uniqueness | 0 collisions across 10,000 sessions (256-bit) |

### Attack Resistance

12 of 14 identified attack vectors are fully mitigated; 2 are partially
mitigated with identified remediation paths:

| Vector | Status | Mitigation |
|--------|--------|------------|
| Replay attack | ✓ Mitigated | Per-session 256-bit nonce + TTL |
| MitM (CMAP) | ✓ Mitigated | Domain-bound challenge + Ed25519 |
| Sybil attack | ✓ Mitigated | Biometric binding, accountability chain |
| Agent impersonation | ✓ Mitigated | DID-bound Ed25519 + challenge–response |
| AL escalation | ✓ Mitigated | Attested AL (signed VC) + type ceiling |
| Delegation forgery | ✓ Mitigated | Ed25519 signature at each chain link |
| Credential forgery | ✓ Mitigated | Issuer Ed25519 over canonical digest |
| Audit tampering | ✓ Mitigated | Hash chain + per-event signature |
| Phishing metaverse | ◐ Partial | Domain binding; needs mutual platform auth |
| Agent collusion | ◐ Partial | Audit correlation; needs threshold signatures |

---

## Performance Summary

All measurements: single-threaded, `time.perf_counter()`, Ubuntu 24.04, x86-64.

### Protocol Latency

| Protocol | Latency (ms) | Throughput (sess/s) |
|----------|-------------|-------------------|
| AGP (Avatar Genesis) | 0.259 | 3,857 |
| CMAP (Cross-Metaverse Auth) | 0.246 | 4,073 |
| PPAP (ZK Attribute Proof) | 0.080 | 12,500 |
| CPP (Credential Portability) | 0.318 | 3,145 |
| AAP (Agent Authentication) | 0.375 | 2,665 |
| **Full lifecycle** | **1.524** | **656** |

### Scalability

| Metric | Regression | R² |
|--------|-----------|-----|
| Delegation chain (per link) | `T(d) = 0.1246d + 0.0048` ms | 0.9987 |
| Audit verification (per event) | `T(n) = 0.1347n + 0.340` ms | 0.9999 |
| Agent creation | O(1) per agent, 0.165 ms | — |
| Agent registry lookup | O(1) amortised, 0.001 ms | — |

### Storage

| Entity | Footprint |
|--------|-----------|
| Human (DID + VC + biometric) | 2,450 B |
| Avatar (DID + genesis VC) | 2,580 B |
| Agent (DID + delegation + VC) | 3,038 B |
| Full identity graph | 8,068 B |
| Audit event | 620 B |

### On-Chain Cost (Full Identity Lifecycle)

| Chain | Cost (USD) |
|-------|-----------|
| Ethereum L1 | $10.10 |
| Arbitrum L2 | $0.034 |
| Polygon PoS | $0.003 |

---

## Formal Definitions

### Quaternary World Model

```
W = {H, P, D, C}
```

where `H` (Human) encompasses biological identities, `P` (Physical) encompasses
hardware devices, `D` (Digital) encompasses avatars and digital assets, and
`C` (Creative) encompasses autonomous agents.

### Identity-Binding Function

```
β : W × W → {0,1}
```

Six valid bindings: `β(H,P) = β(H,D) = β(H,C) = β(P,D) = β(C,D) = β(C,C) = 1`.
All other pairs evaluate to 0.

### Authentication Predicate (AAP)

```
Auth(A, action) ⟺
    VerifySig(DID_A) ∧
    action ∈ Caps(A) ∧
    AL_attested(A) permits action ∧
    ValidDeleg(A → h), h ∈ E_H
```

### Accountability Invariant

```
∀ a ∃ h ∈ E_H, p : Trace(a) → h ∧ BioVerify(h, p) = true
```

### Autonomy Boundedness

```
executable(a) = capabilities(a) ∩ permitted(AL(a))
delegate(AL_i → AL_j) ⟺ j ≤ i
```

---

## Limitations

1. **ZK proof model:** PPAP provides HVZK in the Random Oracle Model, which is
   weaker than simulation-extractable NIZK (Groth16, Plonk). For financial
   settlement, Bulletproofs or BBS+ should be integrated.

2. **BLS performance:** BLS12-381 via `py_ecc` is ~2,000× slower than Ed25519
   due to pure-Python pairing arithmetic. The `blst` library (Rust/C) would
   yield ~195× improvement.

3. **VDR implementation:** The current Verifiable Data Registry is in-memory.
   Production deployment requires on-chain anchoring (Ethereum L2 recommended).

4. **Biometric simulation:** Biometric verification uses SHA-256 template
   comparison. Production requires ISO/IEC 24745-compliant systems with
   liveness detection.

5. **Partial mitigations:** Phishing metaverse (needs mutual platform auth)
   and agent collusion (needs threshold signatures) remain partially mitigated.

6. **Single-threaded evaluation:** Multi-core parallelism would increase
   throughput beyond the reported 656 ops/s.

---

## Acknowledgements

This work was supported by the National Natural Science Foundation of China
(No. U22B2029) and the Open Research Fund of the State Key Laboratory of
Blockchain and Data Security, Zhejiang University.

---

## License

This project is released for academic and research purposes. See [LICENSE](LICENSE)
for details.
