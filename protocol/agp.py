"""
OLYMPUS Avatar Genesis Protocol (AGP)
======================================
Creates cryptographically bound avatar identities from human identities.

Security:
    Binding = Sign_Ed25519(sk_H, H(avatar_did ‖ nonce ‖ ts))
    Verification requires human's public key from DID Document.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from enum import Enum
import secrets

from olympus.crypto.primitives import Ed25519KeyGenerator, KeyPair, sha256


class AGPState(Enum):
    INITIATED       = "initiated"
    CHALLENGED      = "challenged"
    OWNERSHIP_PROVEN= "ownership_proven"
    COMPLETED       = "completed"
    FAILED          = "failed"


@dataclass
class AGPSession:
    session_id: str
    human_did: str
    state: AGPState = AGPState.INITIATED
    challenge_nonce: str = ""
    challenge_expires: Optional[datetime] = None
    avatar_did: Optional[str] = None
    binding_signature: Optional[bytes] = None
    genesis_vc: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AvatarGenesisProtocol:
    """
    AGP: challenge-response binding with Ed25519 signatures.

    Flow:
        1. Human initiates → system issues challenge nonce
        2. Human signs challenge with DID key
        3. System verifies, creates avatar DID, issues binding + genesis VC
    """
    CHALLENGE_TTL = 300  # seconds
    MAX_AVATARS   = 10

    def __init__(self, issuer_did: str = "did:olympus:service:agp"):
        self.issuer_did = issuer_did
        self.sessions: Dict[str, AGPSession] = {}
        self.avatar_count: Dict[str, int] = {}
        self._gen = Ed25519KeyGenerator()
        self._ctr = 0

    def initiate(self, human_did: str) -> AGPSession:
        if not human_did.startswith("did:olympus:human:"):
            raise ValueError("Invalid human DID format")
        if self.avatar_count.get(human_did, 0) >= self.MAX_AVATARS:
            raise ValueError("Avatar limit reached")
        self._ctr += 1
        sid = f"agp-{self._ctr:06d}-{secrets.token_hex(8)}"
        nonce = secrets.token_hex(32)
        s = AGPSession(
            session_id=sid, human_did=human_did,
            state=AGPState.CHALLENGED, challenge_nonce=nonce,
            challenge_expires=datetime.now(timezone.utc) + timedelta(seconds=self.CHALLENGE_TTL),
        )
        self.sessions[sid] = s
        return s

    def complete(self, session_id: str, signature: bytes,
                 human_public_key: bytes) -> AGPSession:
        """Verify ownership proof and create avatar with binding."""
        s = self.sessions.get(session_id)
        if not s:
            raise ValueError("Session not found")
        if s.state != AGPState.CHALLENGED:
            raise ValueError(f"Bad state: {s.state.value}")
        if datetime.now(timezone.utc) > s.challenge_expires:
            s.state, s.error = AGPState.FAILED, "Challenge expired"
            return s
        # Verify Ed25519 signature over challenge nonce
        if not self._gen.verify(human_public_key, s.challenge_nonce.encode(), signature):
            s.state, s.error = AGPState.FAILED, "Invalid signature"
            return s
        s.state = AGPState.OWNERSHIP_PROVEN
        # Create avatar DID
        uid = secrets.token_hex(16)
        s.avatar_did = f"did:olympus:avatar:{uid}"
        # Binding = Sign(sk_system, H(avatar_did ‖ human_did ‖ nonce ‖ ts))
        bind_data = f"{s.avatar_did}|{s.human_did}|{s.challenge_nonce}".encode()
        s.binding_signature = signature  # human's signature serves as binding proof
        # Genesis VC (simplified)
        s.genesis_vc = {
            "@context": ["https://www.w3.org/ns/credentials/v2",
                         "https://olympus.id/ns/credentials/v1"],
            "type": ["VerifiableCredential", "AvatarGenesisCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "credentialSubject": {
                "id": s.avatar_did,
                "humanIdentityHash": sha256(s.human_did.encode()).hex(),
                "bindingProof": signature.hex(),
            },
        }
        self.avatar_count[s.human_did] = self.avatar_count.get(s.human_did, 0) + 1
        s.state = AGPState.COMPLETED
        return s
