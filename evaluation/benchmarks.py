"""
OLYMPUS Evaluation Suite
=========================
Performance benchmarks, security evaluation, and comparative analysis
for IEEE TIFS submission.

Metrics:
    1. Protocol latency (AGP, CMAP, PPAP, CPP, AAP)
    2. Cryptographic operation throughput
    3. Delegation chain verification scalability
    4. Audit trail integrity verification cost
    5. Comparative analysis against existing systems
"""
from __future__ import annotations
import time, statistics, secrets, json, sys, os
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

# ── OLYMPUS imports ─────────────────────────────────────────────────────────
from olympus.core.types import (
    AgentType, AutonomyLevel, AgentCapability, DIDType, WorldType,
)
from olympus.crypto.primitives import (
    Ed25519KeyGenerator, Secp256k1KeyGenerator, sha256, MerkleTree,
    SchnorrProof, Commitment, KeyPair, secure_random,
)
from olympus.did.method import OlympusDIDMethod
from olympus.vc.credential import CredentialIssuer, VerifiableCredential
from olympus.vc.presentation import (
    VerifiablePresentation, PresentationSigner, PresentationVerifier,
)
from olympus.agent.identity import AgentIdentityManager, BiometricModality
from olympus.protocol.agp import AvatarGenesisProtocol
from olympus.protocol.cmap import CrossMetaverseAuthProtocol
from olympus.protocol.ppap import (
    PrivacyPreservingAttributeProof, Predicate, PredicateOp,
)
from olympus.protocol.cpp import CredentialPortabilityProtocol, VDRType
from olympus.protocol.aap import (
    AgentAuthenticationProtocol, DelegationVerifier, DelegationLink,
)
from olympus.forensics.audit import ForensicAuditTrail, ActionType, Severity


# ═══════════════════════════════════════════════════════════════════════════════
#  TIMING UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def _bench(fn, n: int = 100) -> Dict[str, float]:
    """Run fn() n times, return timing stats in ms."""
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return {
        "mean_ms":   round(statistics.mean(times), 4),
        "median_ms": round(statistics.median(times), 4),
        "stdev_ms":  round(statistics.stdev(times), 4) if len(times) > 1 else 0,
        "min_ms":    round(min(times), 4),
        "max_ms":    round(max(times), 4),
        "n":         n,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  1. CRYPTOGRAPHIC PRIMITIVE BENCHMARKS
# ═══════════════════════════════════════════════════════════════════════════════

def bench_crypto(n: int = 200) -> Dict[str, Any]:
    """Benchmark Ed25519, secp256k1 key gen / sign / verify."""
    results = {}
    msg = b"OLYMPUS benchmark message -- 64 bytes of representative data here!!"

    # Ed25519
    ed = Ed25519KeyGenerator()
    kp_ed = ed.generate()
    sig_ed = ed.sign(kp_ed.private_key, msg)
    results["ed25519_keygen"]  = _bench(ed.generate, n)
    results["ed25519_sign"]    = _bench(lambda: ed.sign(kp_ed.private_key, msg), n)
    results["ed25519_verify"]  = _bench(lambda: ed.verify(kp_ed.public_key, msg, sig_ed), n)

    # secp256k1
    sk = Secp256k1KeyGenerator()
    kp_sk = sk.generate()
    sig_sk = sk.sign(kp_sk.private_key, msg)
    results["secp256k1_keygen"] = _bench(sk.generate, n)
    results["secp256k1_sign"]   = _bench(lambda: sk.sign(kp_sk.private_key, msg), n)
    results["secp256k1_verify"] = _bench(lambda: sk.verify(kp_sk.public_key, msg, sig_sk), n)

    # SHA-256
    results["sha256_64B"]  = _bench(lambda: sha256(msg), n * 5)
    results["sha256_1KB"]  = _bench(lambda: sha256(b"x" * 1024), n * 5)

    # Schnorr proof
    ctx = b"bench-context"
    results["schnorr_prove"]  = _bench(lambda: SchnorrProof.prove(msg, ctx), n)
    proof = SchnorrProof.prove(msg, ctx)
    results["schnorr_verify"] = _bench(lambda: SchnorrProof.verify(proof, ctx), n)

    # Merkle tree (16 leaves)
    leaves = [f"attr-{i}".encode() for i in range(16)]
    results["merkle_build_16"]  = _bench(lambda: MerkleTree(leaves), n)
    tree = MerkleTree(leaves)
    p = tree.proof(7)
    results["merkle_verify_16"] = _bench(lambda: MerkleTree.verify_proof(b"attr-7", p, tree.root), n)

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  2. PROTOCOL LATENCY BENCHMARKS
# ═══════════════════════════════════════════════════════════════════════════════

def bench_agp(n: int = 50) -> Dict[str, Any]:
    """Benchmark Avatar Genesis Protocol end-to-end."""
    gen = Ed25519KeyGenerator()
    kp = gen.generate()

    def run():
        agp = AvatarGenesisProtocol()
        human_did = f"did:olympus:human:bench_{secrets.token_hex(4)}"
        s = agp.initiate(human_did)
        sig = gen.sign(kp.private_key, s.challenge_nonce.encode())
        agp.complete(s.session_id, sig, kp.public_key)

    return _bench(run, n)


def bench_cmap(n: int = 50) -> Dict[str, Any]:
    """Benchmark Cross-Metaverse Auth end-to-end."""
    cmap = CrossMetaverseAuthProtocol()
    gen = Ed25519KeyGenerator()
    kp = gen.generate()
    user = "did:olympus:avatar:bench"

    def run():
        s = cmap.request_transition(user, "meta-a", "meta-b")
        payload = sha256(user.encode()) + s.challenge.encode() + b"meta-b"
        sig = gen.sign(kp.private_key, payload)
        cmap.submit_presentation(
            s.session_id, holder_did=user, challenge=s.challenge,
            domain="meta-b", vp_signature=sig, holder_pk=kp.public_key,
            attributes={"did": user, "name": "BenchUser"},
        )

    return _bench(run, n)


def bench_ppap(n: int = 50) -> Dict[str, Any]:
    """Benchmark PPAP predicate proof generation + verification."""
    ppap = PrivacyPreservingAttributeProof()
    creds = {"age": 25, "country": "US", "reputation": 850}

    def run():
        req = ppap.create_request(
            "did:olympus:service:verifier",
            [Predicate("age", PredicateOp.GE, 18),
             Predicate("country", set_values=["US", "UK"])],
        )
        resp = ppap.generate_proof(req, "did:olympus:avatar:prover", creds)
        ppap.verify_proof(resp)

    return _bench(run, n)


def bench_aap(n: int = 50) -> Dict[str, Any]:
    """Benchmark AAP with delegation chain verification."""
    gen = Ed25519KeyGenerator()
    human_kp = gen.generate()
    agent_kp = gen.generate()
    human_did = "did:olympus:human:bench_owner"
    agent_did = "did:olympus:agent:ai:bench_agent"

    dv = DelegationVerifier()
    # Create signed delegation link
    payload = f"{human_did}|{agent_did}|{AutonomyLevel.AL_2.value}".encode()
    sig = gen.sign(human_kp.private_key, payload)
    dv.register(DelegationLink(
        delegator_did=human_did, delegate_did=agent_did,
        autonomy_level=AutonomyLevel.AL_2,
        capabilities=[AgentCapability.INTERACT, AgentCapability.RESPOND],
        signature=sig, delegator_public_key=human_kp.public_key,
    ))

    aap = AgentAuthenticationProtocol(dv)

    def run():
        s = aap.request_auth(agent_did, AgentType.AI, "interact",
                             [AgentCapability.INTERACT])
        agent_sig = gen.sign(agent_kp.private_key, s.challenge.encode())
        aap.submit_proof(s.session_id, agent_signature=agent_sig,
                         agent_public_key=agent_kp.public_key,
                         autonomy_vc_level=AutonomyLevel.AL_2)

    return _bench(run, n)


# ═══════════════════════════════════════════════════════════════════════════════
#  3. SCALABILITY: DELEGATION CHAIN DEPTH
# ═══════════════════════════════════════════════════════════════════════════════

def bench_delegation_depth(max_depth: int = 10, n: int = 30) -> List[Dict[str, Any]]:
    """Measure verification time vs. delegation chain depth."""
    gen = Ed25519KeyGenerator()
    results = []

    for depth in range(1, max_depth + 1):
        dv = DelegationVerifier()
        keys = [gen.generate() for _ in range(depth + 1)]
        dids = ["did:olympus:human:root"] + [f"did:olympus:agent:ai:d{i}" for i in range(depth)]

        for i in range(depth):
            payload = f"{dids[i]}|{dids[i+1]}|{AutonomyLevel.AL_2.value}".encode()
            sig = gen.sign(keys[i].private_key, payload)
            dv.register(DelegationLink(
                delegator_did=dids[i], delegate_did=dids[i+1],
                autonomy_level=AutonomyLevel.AL_2, capabilities=[],
                signature=sig, delegator_public_key=keys[i].public_key,
            ))

        leaf = dids[-1]
        stats = _bench(lambda: dv.verify_chain(leaf), n)
        stats["depth"] = depth
        results.append(stats)

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  4. AUDIT TRAIL SCALABILITY
# ═══════════════════════════════════════════════════════════════════════════════

def bench_audit(sizes: List[int] = None, n: int = 5) -> List[Dict[str, Any]]:
    """Measure audit trail integrity verification time vs. log size."""
    if sizes is None:
        sizes = [100, 500, 1000, 5000]
    gen = Ed25519KeyGenerator()
    key = gen.generate()
    results = []
    for sz in sizes:
        trail = ForensicAuditTrail(signing_key=key)
        for i in range(sz):
            trail.log(f"did:olympus:agent:ai:{i%10}", ActionType.AGENT_ACTION,
                      f"target-{i}", severity=Severity.INFO)
        stats = _bench(lambda: trail.verify_integrity(), n)
        stats["log_size"] = sz
        results.append(stats)
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  5. COMPARATIVE ANALYSIS TABLE
# ═══════════════════════════════════════════════════════════════════════════════

def comparative_table() -> List[Dict[str, Any]]:
    """Feature comparison with existing DID/identity systems."""
    features = [
        "W3C DID Core",
        "W3C VC 2.0",
        "Agent Identity (DID)",
        "Graduated Autonomy",
        "Delegation Chains",
        "Cross-Metaverse Auth",
        "ZK Attribute Proofs",
        "Credential Portability",
        "Human Override",
        "Forensic Audit Trail",
        "Biometric Binding",
        "Quaternary World Model",
    ]
    systems = {
        "OLYMPUS":    [1,1,1,1,1,1,1,1,1,1,1,1],
        "Sovrin":     [1,1,0,0,0,0,1,0,0,0,0,0],
        "PolygonID":  [1,1,0,0,0,0,1,0,0,0,0,0],
        "ION":        [1,1,0,0,0,0,0,0,0,0,0,0],
        "Veramo":     [1,1,0,0,0,0,0,1,0,0,0,0],
        "SpruceID":   [1,1,0,0,0,0,0,0,0,0,0,0],
        "Ceramic/IDX":[1,0,0,0,0,0,0,1,0,0,0,0],
        "ENS":        [0,0,0,0,0,0,0,0,0,0,0,0],
    }
    rows = []
    for sys_name, vals in systems.items():
        row = {"system": sys_name}
        for f, v in zip(features, vals):
            row[f] = "✓" if v else "✗"
        row["score"] = sum(vals)
        rows.append(row)
    return sorted(rows, key=lambda r: r["score"], reverse=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  6. SECURITY EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════

def security_tests() -> Dict[str, Any]:
    """Automated security property verification."""
    results: Dict[str, Any] = {}
    gen = Ed25519KeyGenerator()

    # --- Test 1: Signature unforgeability (Ed25519) ---
    kp = gen.generate()
    msg = b"authentic message"
    sig = gen.sign(kp.private_key, msg)
    results["ed25519_unforgeability"] = {
        "valid_sig_accepts": gen.verify(kp.public_key, msg, sig),
        "tampered_msg_rejects": not gen.verify(kp.public_key, b"tampered", sig),
        "tampered_sig_rejects": not gen.verify(kp.public_key, msg, b"\x00" * 64),
        "wrong_key_rejects": not gen.verify(gen.generate().public_key, msg, sig),
    }

    # --- Test 2: AGP replay protection ---
    agp = AvatarGenesisProtocol()
    human_kp = gen.generate()
    s = agp.initiate("did:olympus:human:test")
    sig = gen.sign(human_kp.private_key, s.challenge_nonce.encode())
    r1 = agp.complete(s.session_id, sig, human_kp.public_key)
    # Replay same session
    try:
        r2 = agp.complete(s.session_id, sig, human_kp.public_key)
        replay_blocked = r2.state.value != "completed"  # Should fail (wrong state)
    except ValueError:
        replay_blocked = True
    results["agp_replay_protection"] = replay_blocked

    # --- Test 3: AAP delegation chain integrity ---
    human_kp2 = gen.generate()
    agent_kp = gen.generate()
    human_did = "did:olympus:human:sec_test"
    agent_did = "did:olympus:agent:ai:sec_test"
    dv = DelegationVerifier()
    payload = f"{human_did}|{agent_did}|{AutonomyLevel.AL_2.value}".encode()
    del_sig = gen.sign(human_kp2.private_key, payload)
    dv.register(DelegationLink(human_did, agent_did, AutonomyLevel.AL_2, [],
                               del_sig, human_kp2.public_key))
    valid_chain, _ = dv.verify_chain(agent_did)

    # Tampered delegation (wrong key)
    dv_bad = DelegationVerifier()
    fake_kp = gen.generate()
    dv_bad.register(DelegationLink(human_did, agent_did, AutonomyLevel.AL_2, [],
                                   del_sig, fake_kp.public_key))  # wrong pk
    tamper_rejected, _ = dv_bad.verify_chain(agent_did)
    results["aap_delegation_integrity"] = {
        "valid_chain_accepts": valid_chain,
        "tampered_chain_rejects": not tamper_rejected,
    }

    # --- Test 4: AAP autonomy ceiling enforcement ---
    aap = AgentAuthenticationProtocol(dv)
    s_aap = aap.request_auth(agent_did, AgentType.AI, "act", [AgentCapability.INTERACT])
    agent_sig = gen.sign(agent_kp.private_key, s_aap.challenge.encode())
    # Try AL-4 (exceeds AI max of AL-3)
    r_over = aap.submit_proof(s_aap.session_id, agent_signature=agent_sig,
                              agent_public_key=agent_kp.public_key,
                              autonomy_vc_level=AutonomyLevel.AL_4)
    results["aap_autonomy_ceiling"] = not r_over.success

    # --- Test 5: Audit trail tamper detection ---
    key = gen.generate()
    trail = ForensicAuditTrail(signing_key=key)
    for i in range(20):
        trail.log("did:olympus:agent:ai:x", ActionType.AGENT_ACTION, f"t{i}")
    ok_before, _ = trail.verify_integrity()
    # Tamper with event #10
    trail.events[10].event_hash = "deadbeef" * 8
    ok_after, last_good = trail.verify_integrity()
    results["audit_tamper_detection"] = {
        "intact_passes": ok_before,
        "tampered_fails": not ok_after,
        "detects_at_index": last_good,
    }

    # --- Test 6: PPAP soundness (cannot prove false predicate) ---
    ppap = PrivacyPreservingAttributeProof()
    req = ppap.create_request("did:olympus:service:v",
                              [Predicate("age", PredicateOp.GE, 21)])
    # Prover is 18 — predicate is false
    resp = ppap.generate_proof(req, "did:olympus:avatar:minor", {"age": 18})
    ok_ppap, verified, failed = ppap.verify_proof(resp)
    results["ppap_soundness"] = {
        "false_predicate_rejected": not ok_ppap,
    }

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_full_evaluation(bench_n: int = 50) -> Dict[str, Any]:
    """Run complete evaluation suite."""
    print("=" * 72)
    print("  OLYMPUS Evaluation Suite — IEEE TIFS Submission")
    print("=" * 72)
    all_results: Dict[str, Any] = {}

    print("\n[1/6] Cryptographic primitive benchmarks …")
    all_results["crypto"] = bench_crypto(bench_n)

    print("[2/6] Protocol latency benchmarks …")
    all_results["agp_latency"] = bench_agp(bench_n)
    all_results["cmap_latency"] = bench_cmap(bench_n)
    all_results["ppap_latency"] = bench_ppap(bench_n)
    all_results["aap_latency"] = bench_aap(bench_n)

    print("[3/6] Delegation chain scalability …")
    all_results["delegation_scalability"] = bench_delegation_depth(10, bench_n)

    print("[4/6] Audit trail scalability …")
    all_results["audit_scalability"] = bench_audit([100, 500, 1000, 2000], max(bench_n // 10, 3))

    print("[5/6] Comparative analysis …")
    all_results["comparison"] = comparative_table()

    print("[6/6] Security tests …")
    all_results["security"] = security_tests()

    return all_results


def print_results(results: Dict[str, Any]):
    """Pretty-print evaluation results."""
    try:
        from tabulate import tabulate
    except ImportError:
        tabulate = None

    print("\n" + "=" * 72)
    print("  RESULTS SUMMARY")
    print("=" * 72)

    # Crypto benchmarks
    print("\n── Cryptographic Primitives (ms) ──")
    rows = []
    for op, stats in results.get("crypto", {}).items():
        rows.append([op, stats["mean_ms"], stats["median_ms"],
                     stats["stdev_ms"], stats["min_ms"], stats["max_ms"]])
    headers = ["Operation", "Mean", "Median", "StdDev", "Min", "Max"]
    if tabulate:
        print(tabulate(rows, headers=headers, floatfmt=".4f"))
    else:
        print(f"{'Operation':<25} {'Mean':>8} {'Median':>8} {'StdDev':>8}")
        for r in rows:
            print(f"{r[0]:<25} {r[1]:>8.4f} {r[2]:>8.4f} {r[3]:>8.4f}")

    # Protocol latency
    print("\n── Protocol Latency (ms) ──")
    for proto in ["agp_latency", "cmap_latency", "ppap_latency", "aap_latency"]:
        s = results.get(proto, {})
        name = proto.replace("_latency", "").upper()
        print(f"  {name:6s}: mean={s.get('mean_ms',0):.3f}  median={s.get('median_ms',0):.3f}  "
              f"stdev={s.get('stdev_ms',0):.3f}")

    # Delegation scalability
    print("\n── Delegation Chain Verification (ms vs. depth) ──")
    for entry in results.get("delegation_scalability", []):
        print(f"  depth={entry['depth']:2d}  mean={entry['mean_ms']:.3f}  "
              f"median={entry['median_ms']:.3f}")

    # Audit scalability
    print("\n── Audit Trail Verification (ms vs. log size) ──")
    for entry in results.get("audit_scalability", []):
        print(f"  events={entry['log_size']:5d}  mean={entry['mean_ms']:.2f}  "
              f"median={entry['median_ms']:.2f}")

    # Comparison table
    print("\n── Comparative Analysis ──")
    comp = results.get("comparison", [])
    if tabulate and comp:
        print(tabulate(comp, headers="keys"))
    else:
        for r in comp:
            print(f"  {r['system']:12s}  score={r['score']}")

    # Security
    print("\n── Security Tests ──")
    sec = results.get("security", {})
    for test_name, outcome in sec.items():
        if isinstance(outcome, dict):
            all_pass = all(v for v in outcome.values() if isinstance(v, bool))
            status = "PASS ✓" if all_pass else "FAIL ✗"
            print(f"  {test_name}: {status}  {outcome}")
        else:
            status = "PASS ✓" if outcome else "FAIL ✗"
            print(f"  {test_name}: {status}")


if __name__ == "__main__":
    results = run_full_evaluation(bench_n=50)
    print_results(results)
    # Save JSON
    with open("evaluation_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to evaluation_results.json")
