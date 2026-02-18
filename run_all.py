#!/usr/bin/env python3
"""
OLYMPUS — run_all.py
=====================
End-to-end integration test + full evaluation suite.
Produces evaluation_results.json for paper figures/tables.
"""
import sys, os, json, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from olympus.core.types import *
from olympus.crypto.primitives import *
from olympus.did.document import *
from olympus.did.method import *
from olympus.vc.credential import *
from olympus.vc.presentation import *
from olympus.agent.identity import *
from olympus.agent.autonomy import *
from olympus.protocol.agp import *
from olympus.protocol.cmap import *
from olympus.protocol.ppap import *
from olympus.protocol.cpp import *
from olympus.protocol.aap import *
from olympus.forensics.audit import *


def integration_test():
    """Full end-to-end scenario: Human → Agent → Action → Audit."""
    print("=" * 72)
    print("  OLYMPUS Integration Test")
    print("=" * 72)
    gen = Ed25519KeyGenerator()

    # ── 1. Create Human DID ─────────────────────────────────────────────
    method = OlympusDIDMethod()
    human_doc, human_kp = method.create(DIDType.HUMAN)
    print(f"\n✓ Human DID created: {human_doc.id}")

    # ── 2. AGP: Create Avatar ───────────────────────────────────────────
    agp = AvatarGenesisProtocol()
    session = agp.initiate(human_doc.id)
    sig = gen.sign(human_kp.private_key, session.challenge_nonce.encode())
    result = agp.complete(session.session_id, sig, human_kp.public_key)
    assert result.state.value == "completed", f"AGP failed: {result.error}"
    print(f"✓ Avatar created via AGP: {result.avatar_did}")

    # ── 3. Issue Verifiable Credential ──────────────────────────────────
    issuer_kp = gen.generate()
    issuer = CredentialIssuer("did:olympus:service:issuer", issuer_kp)
    vc = issuer.issue(result.avatar_did, {
        "avatarName": "TestAvatar",
        "reputationScore": 850,
        "genesisProof": sig.hex()[:32],
    }, "AvatarGenesisCredential")
    ok, errs = issuer.verify(vc)
    assert ok, f"VC verification failed: {errs}"
    print(f"✓ VC issued and verified: {vc.id[:40]}…")

    # ── 4. Create Agent with Biometric Binding ──────────────────────────
    mgr = AgentIdentityManager()
    bio_features = b"simulated_facial_biometric_alice_2024"
    tmpl = mgr.biometric.enroll(human_doc.id, bio_features)
    binding = mgr.biometric.create_binding(human_doc.id, tmpl.template_id)

    agent = mgr.create_agent(
        AgentType.AI, human_doc.id,
        name="Alice's AI", biometric_binding_id=binding.binding_id,
    )
    print(f"✓ Agent created: {agent.did} (AL-{agent.autonomy_level.value})")

    # ── 5. AAP: Authenticate Agent ─────────────────────────────────────
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
    aap_session = aap.request_auth(agent.did, AgentType.AI, "interact",
                                    [AgentCapability.INTERACT])
    agent_sig = gen.sign(agent.key_pair.private_key, aap_session.challenge.encode())
    auth_result = aap.submit_proof(
        aap_session.session_id, agent_signature=agent_sig,
        agent_public_key=agent.key_pair.public_key,
        autonomy_vc_level=agent.autonomy_level,
    )
    assert auth_result.success, f"AAP failed: {auth_result.error}"
    print(f"✓ Agent authenticated via AAP (token: {auth_result.session_token[:20]}…)")

    # ── 6. CMAP: Cross-Metaverse Transition ─────────────────────────────
    cmap = CrossMetaverseAuthProtocol()
    cmap_s = cmap.request_transition(result.avatar_did, "metaverse-a", "metaverse-b")
    vp_payload = sha256(result.avatar_did.encode()) + cmap_s.challenge.encode() + b"metaverse-b"
    vp_sig = gen.sign(human_kp.private_key, vp_payload)
    cmap_r = cmap.submit_presentation(
        cmap_s.session_id, holder_did=result.avatar_did,
        challenge=cmap_s.challenge, domain="metaverse-b",
        vp_signature=vp_sig, holder_pk=human_kp.public_key,
        attributes={"did": result.avatar_did, "reputation": 850},
    )
    assert cmap_r.state.value == "authenticated", f"CMAP failed: {cmap_r.error}"
    print(f"✓ Cross-metaverse auth via CMAP (session: {cmap_r.session_token[:20]}…)")

    # ── 7. PPAP: Privacy-Preserving Proof ───────────────────────────────
    ppap = PrivacyPreservingAttributeProof()
    req = ppap.create_request(
        "did:olympus:service:bar",
        [Predicate("age", PredicateOp.GE, 18),
         Predicate("reputation", PredicateOp.GT, 500)],
        reveal=["country"],
    )
    resp = ppap.generate_proof(req, result.avatar_did,
                               {"age": 25, "reputation": 850, "country": "US"})
    ok_ppap, verified, failed = ppap.verify_proof(resp)
    assert ok_ppap, f"PPAP failed: {failed}"
    print(f"✓ ZK attribute proof via PPAP: verified={verified}, revealed={resp.revealed_attributes}")

    # ── 8. CPP: Credential Portability ──────────────────────────────────
    cpp = CredentialPortabilityProtocol()
    export_kp = gen.generate()
    pc = cpp.export_credential(vc.to_dict(), VDRType.OLYMPUS, export_kp)
    assert cpp.verify_export(pc, export_kp.public_key)
    ok_import, imported = cpp.import_credential(pc, export_kp.public_key)
    assert ok_import, f"CPP import failed: {imported}"
    print(f"✓ Credential exported and imported via CPP")

    # ── 9. Forensic Audit Trail ─────────────────────────────────────────
    audit_key = gen.generate()
    trail = ForensicAuditTrail(signing_key=audit_key)
    trail.log(human_doc.id, ActionType.IDENTITY_CREATE, human_doc.id,
              chain=[human_doc.id])
    trail.log(human_doc.id, ActionType.AGENT_REGISTER, agent.did,
              chain=[human_doc.id])
    trail.log(agent.did, ActionType.AUTH_SUCCESS, "metaverse-b",
              chain=[human_doc.id, agent.did])
    trail.log(agent.did, ActionType.AGENT_ACTION, "interact",
              chain=[human_doc.id, agent.did])
    ok_audit, last = trail.verify_integrity()
    assert ok_audit, "Audit integrity check failed"
    print(f"✓ Audit trail: {len(trail.events)} events, integrity verified")

    # ── 10. Emergency Stop ──────────────────────────────────────────────
    ok_stop, msg = mgr.emergency_stop(
        agent.did, human_doc.id, bio_features, "Testing emergency stop"
    )
    assert ok_stop, f"Emergency stop failed: {msg}"
    assert not agent.is_active
    print(f"✓ Emergency stop executed with biometric verification")

    print("\n" + "=" * 72)
    print("  ALL INTEGRATION TESTS PASSED ✓")
    print("=" * 72)


def main():
    # Integration test
    integration_test()

    # Full evaluation
    print()
    from olympus.evaluation.benchmarks import run_full_evaluation, print_results
    results = run_full_evaluation(bench_n=50)
    print_results(results)

    # Save results
    out_path = os.path.join(os.path.dirname(__file__), "evaluation_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n✓ Results saved to {out_path}")


if __name__ == "__main__":
    main()
