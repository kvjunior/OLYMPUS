"""
OLYMPUS Cross-Metaverse Authentication Protocol (CMAP)
=======================================================
Privacy-preserving cross-platform identity authentication.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone, timedelta
from enum import Enum
import secrets

from olympus.crypto.primitives import Ed25519KeyGenerator, sha256, secure_random


class CMAPState(Enum):
    INITIATED    = "initiated"
    VP_REQUESTED = "vp_requested"
    VP_SUBMITTED = "vp_submitted"
    AUTHENTICATED= "authenticated"
    FAILED       = "failed"


@dataclass
class CMAPSession:
    session_id: str
    user_did: str
    source: str
    target: str
    state: CMAPState = CMAPState.INITIATED
    challenge: str = ""
    expires: Optional[datetime] = None
    session_token: Optional[str] = None
    verified_attributes: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class CrossMetaverseAuthProtocol:
    CHALLENGE_TTL = 120

    def __init__(self):
        self.sessions: Dict[str, CMAPSession] = {}
        self._gen = Ed25519KeyGenerator()
        self._ctr = 0

    def request_transition(self, user_did: str, source: str, target: str) -> CMAPSession:
        self._ctr += 1
        sid = f"cmap-{self._ctr:06d}-{secrets.token_hex(8)}"
        s = CMAPSession(
            session_id=sid, user_did=user_did, source=source, target=target,
            state=CMAPState.VP_REQUESTED,
            challenge=secrets.token_hex(32),
            expires=datetime.now(timezone.utc) + timedelta(seconds=self.CHALLENGE_TTL),
        )
        self.sessions[sid] = s
        return s

    def submit_presentation(self, session_id: str, *,
                            holder_did: str, challenge: str, domain: str,
                            vp_signature: bytes, holder_pk: bytes,
                            attributes: Dict[str, Any]) -> CMAPSession:
        s = self.sessions.get(session_id)
        if not s:
            raise ValueError("Session not found")
        if datetime.now(timezone.utc) > s.expires:
            s.state, s.error = CMAPState.FAILED, "Expired"
            return s
        if challenge != s.challenge:
            s.state, s.error = CMAPState.FAILED, "Challenge mismatch"
            return s
        if domain != s.target:
            s.state, s.error = CMAPState.FAILED, "Domain mismatch"
            return s
        # Verify holder signature over (hash ‖ challenge ‖ domain)
        payload = sha256(holder_did.encode()) + challenge.encode() + domain.encode()
        if not self._gen.verify(holder_pk, payload, vp_signature):
            s.state, s.error = CMAPState.FAILED, "Invalid VP signature"
            return s
        s.verified_attributes = attributes
        # Cryptographically random session token (not hash-based)
        s.session_token = f"cmap_{secrets.token_hex(32)}"
        s.state = CMAPState.AUTHENTICATED
        return s
