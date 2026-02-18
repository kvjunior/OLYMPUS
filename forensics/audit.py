"""
OLYMPUS Forensics & Audit Trail
=================================
Tamper-evident logging with Merkle-chain integrity.

Integrity:  H_i = Hash(event_i ‖ H_{i-1}),  H_0 = genesis
Accountability:  every event links to a human principal via delegation chain.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from enum import Enum, auto
import json, hashlib, uuid

from olympus.crypto.primitives import sha256, Ed25519KeyGenerator, KeyPair


class ActionType(Enum):
    IDENTITY_CREATE = auto(); IDENTITY_REVOKE = auto()
    AUTH_SUCCESS = auto(); AUTH_FAILURE = auto()
    DELEGATION_CREATE = auto(); DELEGATION_REVOKE = auto()
    CREDENTIAL_ISSUE = auto(); CREDENTIAL_VERIFY = auto()
    AGENT_REGISTER = auto(); AGENT_ACTION = auto()
    AUTONOMY_CHANGE = auto(); HUMAN_OVERRIDE = auto()
    EMERGENCY_STOP = auto(); METAVERSE_TRANSITION = auto()
    ZK_PROOF_GENERATE = auto(); ZK_PROOF_VERIFY = auto()


class Severity(Enum):
    INFO = 0; NOTICE = 1; WARNING = 2; ALERT = 3; CRITICAL = 4; EMERGENCY = 5


@dataclass
class AuditEvent:
    event_id: str
    timestamp: datetime
    actor_did: str
    action: ActionType
    target: str
    severity: Severity
    evidence_hash: str
    delegation_chain: List[str]
    signature: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    event_hash: str = ""

    def compute_hash(self, prev: str) -> str:
        data = json.dumps({
            "id": self.event_id, "ts": self.timestamp.isoformat(),
            "actor": self.actor_did, "action": self.action.name,
            "target": self.target, "evidence": self.evidence_hash,
            "prev": prev,
        }, sort_keys=True).encode()
        return sha256(data).hex()


class ForensicAuditTrail:
    """Append-only, hash-chained audit log with Ed25519 event signing."""

    GENESIS = "0" * 64

    def __init__(self, signing_key: Optional[KeyPair] = None):
        self.events: List[AuditEvent] = []
        self._prev = self.GENESIS
        self._gen = Ed25519KeyGenerator()
        self._key = signing_key

    def log(self, actor: str, action: ActionType, target: str, *,
            severity: Severity = Severity.INFO,
            evidence: str = "", chain: Optional[List[str]] = None,
            meta: Optional[Dict[str, Any]] = None) -> AuditEvent:
        ev = AuditEvent(
            event_id=str(uuid.uuid4()), timestamp=datetime.now(timezone.utc),
            actor_did=actor, action=action, target=target,
            severity=severity, evidence_hash=evidence or sha256(b"").hex(),
            delegation_chain=chain or [],
            metadata=meta or {},
        )
        ev.prev_hash = self._prev
        ev.event_hash = ev.compute_hash(self._prev)
        if self._key and self._key.private_key:
            ev.signature = self._gen.sign(self._key.private_key, ev.event_hash.encode())
        self._prev = ev.event_hash
        self.events.append(ev)
        return ev

    def verify_integrity(self) -> Tuple[bool, int]:
        """Verify full chain. Returns (valid, last_good_index)."""
        prev = self.GENESIS
        for i, ev in enumerate(self.events):
            expected = ev.compute_hash(prev)
            if expected != ev.event_hash:
                return False, i - 1
            if ev.signature and self._key:
                if not self._gen.verify(self._key.public_key, ev.event_hash.encode(), ev.signature):
                    return False, i - 1
            prev = ev.event_hash
        return True, len(self.events) - 1

    def query_by_actor(self, did: str) -> List[AuditEvent]:
        return [e for e in self.events if e.actor_did == did]

    def query_by_action(self, action: ActionType) -> List[AuditEvent]:
        return [e for e in self.events if e.action == action]

    def query_by_severity(self, min_sev: Severity) -> List[AuditEvent]:
        return [e for e in self.events if e.severity.value >= min_sev.value]

    def trace_to_human(self, agent_did: str) -> Optional[str]:
        """Find human principal from audit events."""
        for ev in reversed(self.events):
            if ev.actor_did == agent_did and ev.delegation_chain:
                for d in ev.delegation_chain:
                    if d.startswith("did:olympus:human:"):
                        return d
        return None


# Need Tuple import for type hint
from typing import Tuple
