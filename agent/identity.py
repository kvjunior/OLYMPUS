"""
OLYMPUS Agent Identity Framework
==================================
Novel: first DID-based identity system for autonomous agents
with biometric-verified human accountability.

Accountability invariant:
    ∀ agent action a : ∃ human h, biometric proof p :
        Trace(a) → h  ∧  BiometricVerify(h, p) = true
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Set, Tuple
from datetime import datetime, timezone, timedelta
import hashlib, hmac, secrets, uuid

from olympus.core.types import (
    AgentType, AutonomyLevel, AgentCapability, CapabilityRiskLevel,
    CAPABILITY_RISK, BiometricModality, LivenessCheckType, DIDType,
)
from olympus.crypto.primitives import sha256, secure_random, Ed25519KeyGenerator, KeyPair


# ═══════════════════════════════════════════════════════════════════════════════
#  BIOMETRIC VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

class BiometricResult:
    SUCCESS = "success"
    FAILURE_NO_MATCH = "failure_no_match"
    FAILURE_LIVENESS = "failure_liveness"
    FAILURE_QUALITY = "failure_quality"


@dataclass
class BiometricTemplate:
    template_id: str
    human_did: str
    modality: BiometricModality
    template_hash: bytes           # H(features) — never store raw biometrics
    quality_score: float
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


@dataclass
class BiometricBinding:
    binding_id: str
    human_did: str
    template_id: str
    bound_entities: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_valid(self) -> bool:
        return True  # Could add expiry logic


class BiometricVerifier:
    """Simulated biometric verification (ISO/IEC 24745 template protection)."""

    MATCH_THRESHOLD = 0.75

    def __init__(self):
        self.templates: Dict[str, BiometricTemplate] = {}
        self.bindings: Dict[str, BiometricBinding] = {}

    def enroll(self, human_did: str, features: bytes,
               modality: BiometricModality = BiometricModality.FACIAL,
               quality: float = 0.9) -> BiometricTemplate:
        tid = f"tmpl-{secrets.token_hex(8)}"
        tmpl = BiometricTemplate(
            template_id=tid, human_did=human_did, modality=modality,
            template_hash=sha256(features), quality_score=quality,
        )
        self.templates[tid] = tmpl
        return tmpl

    def create_binding(self, human_did: str, template_id: str) -> BiometricBinding:
        bid = f"bind-{secrets.token_hex(8)}"
        b = BiometricBinding(binding_id=bid, human_did=human_did, template_id=template_id)
        self.bindings[bid] = b
        return b

    def bind_entity(self, binding_id: str, entity_did: str):
        b = self.bindings.get(binding_id)
        if b and entity_did not in b.bound_entities:
            b.bound_entities.append(entity_did)

    def verify(self, binding_id: str, features: bytes) -> Tuple[str, float, str]:
        """Returns (result, confidence, proof_hash)."""
        b = self.bindings.get(binding_id)
        if not b:
            return BiometricResult.FAILURE_NO_MATCH, 0.0, ""
        tmpl = self.templates.get(b.template_id)
        if not tmpl or not tmpl.is_active:
            return BiometricResult.FAILURE_NO_MATCH, 0.0, ""
        submitted_hash = sha256(features)
        score = 1.0 if hmac.compare_digest(submitted_hash, tmpl.template_hash) else 0.0
        if score >= self.MATCH_THRESHOLD:
            proof = sha256(submitted_hash + secrets.token_bytes(16)).hex()
            return BiometricResult.SUCCESS, score, proof
        return BiometricResult.FAILURE_NO_MATCH, score, ""


# ═══════════════════════════════════════════════════════════════════════════════
#  DELEGATION CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DelegationRecord:
    delegation_id: str
    delegator_did: str
    delegate_did: str
    capabilities: List[AgentCapability]
    max_autonomy: AutonomyLevel
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    signature: Optional[bytes] = None        # Ed25519 signature by delegator

    @property
    def is_valid(self) -> bool:
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True


@dataclass
class DelegationChain:
    """Immutable snapshot of a delegation path ending at a human principal."""
    path: List[str]
    human_principal: str
    chain_hash: str
    records: List[DelegationRecord] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
#  AGENT IDENTITY
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AgentIdentity:
    did: str
    agent_type: AgentType
    owner_did: str
    autonomy_level: AutonomyLevel
    capabilities: Set[AgentCapability]
    name: str = ""
    description: str = ""
    delegation_chain: List[str] = field(default_factory=list)
    sub_agents: List[str] = field(default_factory=list)
    biometric_binding_id: Optional[str] = None
    key_pair: Optional[KeyPair] = None
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    root_owner: str = ""
    delegation_received: Optional[DelegationRecord] = None

    def __post_init__(self):
        if not self.root_owner:
            self.root_owner = self.owner_did

    @property
    def human_principal(self) -> str:
        return self.root_owner

    @property
    def requires_human_approval(self) -> bool:
        return self.autonomy_level.requires_human_approval

    def has_capability(self, cap: AgentCapability) -> bool:
        return cap in self.capabilities

    def deactivate(self):
        self.is_active = False

    def suspend(self, reason: str = ""):
        self.is_active = False

    def get_delegation_chain_snapshot(self) -> DelegationChain:
        path = self.delegation_chain + [self.did]
        chain_data = "|".join(path)
        return DelegationChain(
            path=path, human_principal=self.root_owner,
            chain_hash=sha256(chain_data.encode()).hex(),
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  DEFAULT CAPABILITY SETS
# ═══════════════════════════════════════════════════════════════════════════════

_CAPS: Dict[AgentType, Set[AgentCapability]] = {
    AgentType.NPC: {AgentCapability.INTERACT, AgentCapability.RESPOND,
                    AgentCapability.FOLLOW_SCRIPT, AgentCapability.ANIMATE},
    AgentType.AI: {AgentCapability.INTERACT, AgentCapability.RESPOND,
                   AgentCapability.LEARN, AgentCapability.RECOMMEND,
                   AgentCapability.GENERATE},
    AgentType.AUTONOMOUS: {AgentCapability.INTERACT, AgentCapability.RESPOND,
                           AgentCapability.EXECUTE_TASK, AgentCapability.DELEGATE,
                           AgentCapability.MANAGE_RESOURCES},
    AgentType.SERVICE: {AgentCapability.EXECUTE_CONTRACT, AgentCapability.MANAGE_ASSETS,
                        AgentCapability.GOVERNANCE_VOTE, AgentCapability.TRANSFER_VALUE},
}


# ═══════════════════════════════════════════════════════════════════════════════
#  AGENT IDENTITY MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class AgentIdentityManager:
    """
    Central manager for agent lifecycle.

    Enforces:
        • Autonomy ceiling per agent type
        • Delegation only to ≤ autonomy level
        • Biometric verification for CRITICAL operations
        • Human override at any autonomy level
    """

    def __init__(self):
        self.agents: Dict[str, AgentIdentity] = {}
        self.biometric: BiometricVerifier = BiometricVerifier()
        self._keygen = Ed25519KeyGenerator()

    def create_agent(self, agent_type: AgentType, owner_did: str, *,
                     name: str = "", description: str = "",
                     biometric_binding_id: Optional[str] = None,
                     capabilities: Optional[Set[AgentCapability]] = None,
                     autonomy: Optional[AutonomyLevel] = None) -> AgentIdentity:
        al = autonomy or agent_type.default_autonomy
        if al.value > agent_type.max_autonomy.value:
            raise ValueError(f"AL-{al.value} exceeds max for {agent_type.value}")
        uid = secrets.token_hex(16)
        did = f"did:olympus:agent:{agent_type.value}:{uid}"
        kp = self._keygen.generate()
        caps = capabilities if capabilities is not None else _CAPS.get(agent_type, set())
        agent = AgentIdentity(
            did=did, agent_type=agent_type, owner_did=owner_did,
            autonomy_level=al, capabilities=caps,
            name=name, description=description,
            delegation_chain=[owner_did], biometric_binding_id=biometric_binding_id,
            key_pair=kp, root_owner=owner_did,
        )
        self.agents[did] = agent
        return agent

    def authorize_action(self, agent_did: str, capability: AgentCapability,
                         *, biometric_features: Optional[bytes] = None
                         ) -> Tuple[bool, str, Optional[str]]:
        """Returns (allowed, reason, biometric_proof)."""
        agent = self.agents.get(agent_did)
        if not agent or not agent.is_active:
            return False, "Agent not found or inactive", None
        if not agent.has_capability(capability):
            return False, f"Missing capability: {capability.value}", None
        risk = CAPABILITY_RISK.get(capability, CapabilityRiskLevel.LOW)
        if risk.value >= CapabilityRiskLevel.HIGH.value:
            if not biometric_features:
                return False, "Biometric required for high-risk action", None
            bid = agent.biometric_binding_id
            if not bid:
                return False, "No biometric binding", None
            result, conf, proof = self.biometric.verify(bid, biometric_features)
            if result != BiometricResult.SUCCESS:
                return False, f"Biometric failed: {result}", None
            return True, "Authorized with biometric", proof
        return True, "Authorized", None

    def delegate(self, delegator_did: str, delegate_did: str,
                 capabilities: List[AgentCapability],
                 max_autonomy: AutonomyLevel) -> Tuple[Optional[DelegationRecord], str]:
        delegator = self.agents.get(delegator_did)
        delegate = self.agents.get(delegate_did)
        if not delegator or not delegate:
            return None, "Agent not found"
        if not delegator.autonomy_level.can_delegate_to(max_autonomy):
            return None, "Cannot delegate to higher autonomy"
        for cap in capabilities:
            if not delegator.has_capability(cap):
                return None, f"Delegator lacks capability: {cap.value}"
        rec = DelegationRecord(
            delegation_id=f"del-{secrets.token_hex(8)}",
            delegator_did=delegator_did, delegate_did=delegate_did,
            capabilities=capabilities, max_autonomy=max_autonomy,
        )
        # Sign delegation with delegator's key
        if delegator.key_pair and delegator.key_pair.private_key:
            payload = f"{delegator_did}|{delegate_did}|{max_autonomy.value}".encode()
            rec.signature = self._keygen.sign(delegator.key_pair.private_key, payload)
        delegate.delegation_received = rec
        delegate.delegation_chain = delegator.delegation_chain + [delegator_did]
        delegate.root_owner = delegator.root_owner
        delegator.sub_agents.append(delegate_did)
        return rec, "Delegation successful"

    def emergency_stop(self, agent_did: str, human_did: str,
                       biometric_features: bytes, reason: str) -> Tuple[bool, str]:
        agent = self.agents.get(agent_did)
        if not agent:
            return False, "Agent not found"
        if human_did not in [agent.root_owner] + agent.delegation_chain:
            return False, "Human not in accountability chain"
        bid = agent.biometric_binding_id
        if not bid:
            return False, "No biometric binding"
        result, _, proof = self.biometric.verify(bid, biometric_features)
        if result != BiometricResult.SUCCESS:
            return False, f"Biometric failed: {result}"
        agent.suspend(f"EMERGENCY STOP by {human_did}: {reason}")
        for sub_did in agent.sub_agents:
            sub = self.agents.get(sub_did)
            if sub:
                sub.suspend(f"Cascaded stop from {agent_did}")
        return True, f"Emergency stop executed (proof: {proof[:16]}…)"
