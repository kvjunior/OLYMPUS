"""
OLYMPUS Autonomy Management — graduated AL-0 … AL-4 enforcement.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable, Tuple
from datetime import datetime, timezone, timedelta
from enum import Enum

from olympus.core.types import AutonomyLevel, AgentCapability
from olympus.agent.identity import AgentIdentity


class ActionStatus(Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED   = "failed"
    EXPIRED  = "expired"


@dataclass
class ActionRequest:
    id: str
    agent_did: str
    action_type: str
    action_params: Dict[str, Any]
    required_capabilities: List[AgentCapability]
    status: ActionStatus = ActionStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    approved_by: Optional[str] = None

    def is_expired(self) -> bool:
        return self.expires_at is not None and datetime.now(timezone.utc) > self.expires_at


@dataclass
class AutonomyBoundary:
    allowed_actions: List[str] = field(default_factory=list)
    max_value_transfer: Optional[float] = None
    daily_action_limit: Optional[int] = None
    prohibited_actions: List[str] = field(default_factory=list)

    def is_action_allowed(self, action: str) -> bool:
        if action in self.prohibited_actions:
            return False
        if self.allowed_actions and action not in self.allowed_actions:
            return False
        return True


class AutonomyManager:
    """Enforces autonomy boundaries with audit logging."""

    def __init__(self):
        self.pending: Dict[str, ActionRequest] = {}
        self.audit: List[Dict[str, Any]] = []
        self.boundaries: Dict[str, AutonomyBoundary] = {}
        self.daily_counts: Dict[str, int] = {}
        self._ctr = 0

    def set_boundary(self, agent_did: str, b: AutonomyBoundary):
        self.boundaries[agent_did] = b

    def request_action(self, agent: AgentIdentity, action_type: str,
                       action_params: Dict[str, Any]) -> ActionRequest:
        self._ctr += 1
        req = ActionRequest(
            id=f"req-{self._ctr:08d}", agent_did=agent.did,
            action_type=action_type, action_params=action_params,
            required_capabilities=[],
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        can, reason = self._can_auto_approve(agent, action_type, action_params)
        if can:
            req.status = ActionStatus.APPROVED
            req.approved_by = "auto"
            self._log(agent, action_type, action_params, "auto", "approved")
        else:
            self.pending[req.id] = req
            self._log(agent, action_type, action_params, None, f"pending: {reason}")
        return req

    def approve(self, req_id: str, approver: str) -> Tuple[bool, str]:
        req = self.pending.pop(req_id, None)
        if not req:
            return False, "Not found"
        if req.is_expired():
            return False, "Expired"
        req.status = ActionStatus.APPROVED
        req.approved_by = approver
        return True, "Approved"

    def emergency_override(self, agent_did: str, human_did: str):
        to_rm = [k for k, v in self.pending.items() if v.agent_did == agent_did]
        for k in to_rm:
            del self.pending[k]
        self.audit.append({"type": "emergency_override", "agent": agent_did,
                           "by": human_did, "ts": datetime.now(timezone.utc).isoformat()})

    # ── internals ───────────────────────────────────────────────────────────

    def _can_auto_approve(self, agent: AgentIdentity, action: str,
                          params: Dict[str, Any]) -> Tuple[bool, str]:
        al = agent.autonomy_level
        if al.value <= 1:
            return False, f"AL-{al.value} requires human approval"
        b = self.boundaries.get(agent.did)
        if b:
            if not b.is_action_allowed(action):
                return False, "Action not in boundary"
            if b.max_value_transfer:
                if params.get("value", 0) > b.max_value_transfer:
                    return False, "Value exceeds limit"
            if b.daily_action_limit:
                if self.daily_counts.get(agent.did, 0) >= b.daily_action_limit:
                    return False, "Daily limit reached"
        self.daily_counts[agent.did] = self.daily_counts.get(agent.did, 0) + 1
        return True, f"AL-{al.value} auto-approved"

    def _log(self, agent, action, params, approver, result):
        self.audit.append({
            "agent": agent.did, "action": action,
            "al": agent.autonomy_level.value, "approver": approver,
            "result": result, "ts": datetime.now(timezone.utc).isoformat(),
        })
