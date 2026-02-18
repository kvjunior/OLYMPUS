"""
OLYMPUS Core Types and Enumerations
====================================
Canonical type definitions for the OLYMPUS architecture.

Mathematical Foundation:
    W = {H, P, D, C}                   — Quaternary World Model
    L = {L0, L1, L2, L3, L4, L5}       — Purdue security layers
    A = {AL0, AL1, AL2, AL3, AL4}       — Autonomy levels
    β : W × W → {0,1}                  — Identity binding function

References:
    [1] Wang et al. (2023) — Ternary World Model (extended to Quaternary)
    [2] ISA/IEC 62443       — Purdue Enterprise Reference Architecture
    [3] W3C DID Core v1.0 Specification
"""

from __future__ import annotations

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any, Tuple
from datetime import datetime, timezone
import hashlib, json


# ═══════════════════════════════════════════════════════════════════════════════
#  QUATERNARY WORLD MODEL
# ═══════════════════════════════════════════════════════════════════════════════

class WorldType(Enum):
    """
    Quaternary World Model — Extension of Wang et al. (2023).

    Theorem (Necessity of Creative World):
        Let Ψ be the set of autonomous agent behaviours.  No composition
        f : HUMAN × PHYSICAL × DIGITAL → Ψ can satisfy simultaneously:
        (i)   independent key management,
        (ii)  graduated autonomy with human override,
        (iii) delegation-chain accountability.
        Hence a fourth partition C is necessary.  □
    """
    HUMAN    = "human"      # Biological identity, biometrics
    PHYSICAL = "physical"   # Hardware devices, IoT, XR equipment
    DIGITAL  = "digital"    # Avatars, digital assets
    CREATIVE = "creative"   # Autonomous agents, NPCs, AI systems


class DIDType(Enum):
    """DID type classification — one per world."""
    HUMAN  = "human"
    DEVICE = "device"
    AVATAR = "avatar"
    AGENT  = "agent"

    @property
    def world(self) -> WorldType:
        return {
            "human":  WorldType.HUMAN,
            "device": WorldType.PHYSICAL,
            "avatar": WorldType.DIGITAL,
            "agent":  WorldType.CREATIVE,
        }[self.value]


# ═══════════════════════════════════════════════════════════════════════════════
#  PURDUE SECURITY MODEL
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityBoundary(Enum):
    TEE_HARDWARE           = "tee_hardware"
    CONSENSUS              = "consensus"
    IDENTITY_VALIDATION    = "identity_validation"
    CRYPTOGRAPHIC_PROOF    = "cryptographic_proof"
    PROTOCOL_VERIFICATION  = "protocol_verification"
    APPLICATION_FIREWALL   = "application_firewall"


class LayerType(Enum):
    L0_PHYSICAL    = 0
    L1_CONTROL     = 1
    L2_SUPERVISORY = 2
    L3_OPERATIONS  = 3
    L4_BUSINESS    = 4
    L5_ENTERPRISE  = 5


# ═══════════════════════════════════════════════════════════════════════════════
#  AUTONOMY LEVELS
# ═══════════════════════════════════════════════════════════════════════════════

class AutonomyLevel(Enum):
    """
    Graduated autonomy  AL-0 … AL-4.

    Formal:
        executable(a) = capabilities(a) ∩ permitted(AL(a))
        delegate(AL_i → AL_j)  ⟺  j ≤ i
    """
    AL_0 = 0   # Fully Human-Controlled
    AL_1 = 1   # Human-Supervised
    AL_2 = 2   # Semi-Autonomous
    AL_3 = 3   # Supervised Autonomous
    AL_4 = 4   # Fully Autonomous

    @property
    def requires_human_approval(self) -> bool:
        return self.value <= 1

    @property
    def max_unsupervised_actions(self) -> int:
        return {0: 0, 1: 1, 2: 10, 3: 100, 4: 2**31}[self.value]

    def can_delegate_to(self, target: AutonomyLevel) -> bool:
        return target.value <= self.value


# ═══════════════════════════════════════════════════════════════════════════════
#  AGENT TYPES & CAPABILITIES
# ═══════════════════════════════════════════════════════════════════════════════

class AgentType(Enum):
    NPC        = "npc"
    AI         = "ai"
    AUTONOMOUS = "autonomous"
    SERVICE    = "service"

    @property
    def default_autonomy(self) -> AutonomyLevel:
        return {
            "npc": AutonomyLevel.AL_1,
            "ai":  AutonomyLevel.AL_2,
            "autonomous": AutonomyLevel.AL_3,
            "service":    AutonomyLevel.AL_4,
        }[self.value]

    @property
    def max_autonomy(self) -> AutonomyLevel:
        return {
            "npc": AutonomyLevel.AL_2,
            "ai":  AutonomyLevel.AL_3,
            "autonomous": AutonomyLevel.AL_4,
            "service":    AutonomyLevel.AL_4,
        }[self.value]


class AgentCapability(Enum):
    INTERACT        = "interact"
    RESPOND         = "respond"
    FOLLOW_SCRIPT   = "follow_script"
    ANIMATE         = "animate"
    LEARN           = "learn"
    RECOMMEND       = "recommend"
    GENERATE        = "generate"
    EXECUTE_TASK    = "execute_task"
    DELEGATE        = "delegate"
    MANAGE_RESOURCES= "manage_resources"
    EXECUTE_CONTRACT= "execute_contract"
    MANAGE_ASSETS   = "manage_assets"
    GOVERNANCE_VOTE = "governance_vote"
    TRANSFER_VALUE  = "transfer_value"


class CapabilityRiskLevel(Enum):
    LOW      = 0
    MEDIUM   = 1
    HIGH     = 2
    CRITICAL = 3


CAPABILITY_RISK: Dict[AgentCapability, CapabilityRiskLevel] = {
    AgentCapability.INTERACT:         CapabilityRiskLevel.LOW,
    AgentCapability.RESPOND:          CapabilityRiskLevel.LOW,
    AgentCapability.FOLLOW_SCRIPT:    CapabilityRiskLevel.LOW,
    AgentCapability.ANIMATE:          CapabilityRiskLevel.LOW,
    AgentCapability.LEARN:            CapabilityRiskLevel.MEDIUM,
    AgentCapability.RECOMMEND:        CapabilityRiskLevel.MEDIUM,
    AgentCapability.GENERATE:         CapabilityRiskLevel.MEDIUM,
    AgentCapability.EXECUTE_TASK:     CapabilityRiskLevel.MEDIUM,
    AgentCapability.DELEGATE:         CapabilityRiskLevel.HIGH,
    AgentCapability.MANAGE_RESOURCES: CapabilityRiskLevel.HIGH,
    AgentCapability.EXECUTE_CONTRACT: CapabilityRiskLevel.HIGH,
    AgentCapability.MANAGE_ASSETS:    CapabilityRiskLevel.CRITICAL,
    AgentCapability.GOVERNANCE_VOTE:  CapabilityRiskLevel.CRITICAL,
    AgentCapability.TRANSFER_VALUE:   CapabilityRiskLevel.CRITICAL,
}


# ═══════════════════════════════════════════════════════════════════════════════
#  RELATIONSHIPS
# ═══════════════════════════════════════════════════════════════════════════════

class RelationshipType(Enum):
    OWNS      = "owns"
    DELEGATES = "delegates"
    CONTROLS  = "controls"
    OPERATES  = "operates"
    BINDS     = "binds"


class CredentialStatus(Enum):
    ACTIVE    = "active"
    SUSPENDED = "suspended"
    REVOKED   = "revoked"
    EXPIRED   = "expired"


# ═══════════════════════════════════════════════════════════════════════════════
#  BIOMETRIC MODALITIES
# ═══════════════════════════════════════════════════════════════════════════════

class BiometricModality(Enum):
    FACIAL      = "facial"
    FINGERPRINT = "fingerprint"
    IRIS        = "iris"
    VOICE       = "voice"
    BEHAVIORAL  = "behavioral"
    MULTIMODAL  = "multimodal"


class LivenessCheckType(Enum):
    PASSIVE     = "passive"
    ACTIVE      = "active"
    HARDWARE    = "hardware"
    BEHAVIORAL  = "behavioral"
    MULTIMODAL  = "multimodal"


# ═══════════════════════════════════════════════════════════════════════════════
#  PROTOCOL MESSAGE BASE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProtocolMessage:
    """Base for all OLYMPUS protocol messages."""
    protocol:      str
    version:       str
    message_type:  str
    sender_did:    str
    recipient_did: Optional[str]
    payload:       Dict[str, Any]
    timestamp:     datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    nonce:         str = ""
    signature:     Optional[bytes] = None

    def __post_init__(self):
        if not self.nonce:
            import secrets
            self.nonce = secrets.token_hex(16)

    def canonical_bytes(self) -> bytes:
        data = {
            "protocol": self.protocol, "version": self.version,
            "type": self.message_type, "sender": self.sender_did,
            "recipient": self.recipient_did, "payload": self.payload,
            "timestamp": self.timestamp.isoformat(), "nonce": self.nonce,
        }
        return json.dumps(data, sort_keys=True, default=str).encode()

    def digest(self) -> bytes:
        return hashlib.sha256(self.canonical_bytes()).digest()


# ═══════════════════════════════════════════════════════════════════════════════
#  IDENTITY BINDING
# ═══════════════════════════════════════════════════════════════════════════════

# Valid cross-world binding matrix  β(source, target)
# True iff a direct identity binding is permitted.
VALID_BINDINGS: Dict[Tuple[WorldType, WorldType], bool] = {
    (WorldType.HUMAN,    WorldType.DIGITAL):   True,   # human → avatar
    (WorldType.HUMAN,    WorldType.CREATIVE):  True,   # human → agent (ownership)
    (WorldType.HUMAN,    WorldType.PHYSICAL):  True,   # human → device
    (WorldType.PHYSICAL, WorldType.DIGITAL):   True,   # device → avatar (XR)
    (WorldType.CREATIVE, WorldType.DIGITAL):   True,   # agent → avatar (operation)
    (WorldType.CREATIVE, WorldType.CREATIVE):  True,   # agent → agent (delegation)
}


def is_binding_valid(source: WorldType, target: WorldType) -> bool:
    """Check β(source, target) = 1."""
    return VALID_BINDINGS.get((source, target), False)


# ═══════════════════════════════════════════════════════════════════════════════
#  TYPE ALIASES
# ═══════════════════════════════════════════════════════════════════════════════

DID = str
Signature = bytes
VerificationResult = Tuple[bool, Optional[str]]
