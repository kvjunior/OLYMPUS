"""
OLYMPUS DID Method — ``did:olympus:<type>:<id>``

CRUD operations + VDR (Verifiable Data Registry) interface.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import secrets

from olympus.core.types import DIDType, AgentType, AutonomyLevel
from olympus.crypto.primitives import (
    Ed25519KeyGenerator, KeyPair, sha256, secure_random,
)
from olympus.did.document import DIDDocument, DIDDocumentBuilder, VerificationMethod


@dataclass
class DIDResolutionResult:
    did: str
    document: Optional[DIDDocument] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def found(self) -> bool:
        return self.document is not None


class OlympusDIDMethod:
    """
    ``did:olympus`` method implementation.

    Create / Read / Update / Deactivate lifecycle with in-memory VDR.
    """
    METHOD_NAME = "olympus"

    def __init__(self):
        self._registry: Dict[str, DIDDocument] = {}
        self._key_gen = Ed25519KeyGenerator()

    # ── CREATE ──────────────────────────────────────────────────────────────

    def create(self, did_type: DIDType, *,
               agent_type: Optional[AgentType] = None,
               autonomy_level: Optional[AutonomyLevel] = None,
               owner_did: Optional[str] = None,
               capabilities: Optional[list] = None) -> Tuple[DIDDocument, KeyPair]:
        uid = secrets.token_hex(16)
        if did_type == DIDType.AGENT and agent_type:
            did = f"did:olympus:agent:{agent_type.value}:{uid}"
        else:
            did = f"did:olympus:{did_type.value}:{uid}"
        kp = self._key_gen.generate()
        builder = DIDDocumentBuilder(did).add_key(kp).set_authentication().set_assertion_method()
        if did_type == DIDType.AGENT and agent_type:
            al = autonomy_level or agent_type.default_autonomy
            builder.set_agent_properties(agent_type, al, capabilities or [])
            if owner_did:
                builder.add_delegation(owner_did)
        doc = builder.build()
        self._registry[did] = doc
        return doc, kp

    # ── READ ────────────────────────────────────────────────────────────────

    def resolve(self, did: str) -> DIDResolutionResult:
        doc = self._registry.get(did)
        if doc is None:
            return DIDResolutionResult(did=did, error="notFound")
        if doc.deactivated:
            return DIDResolutionResult(did=did, error="deactivated", metadata={"deactivated": True})
        return DIDResolutionResult(did=did, document=doc, metadata={"versionId": doc.version_id})

    # ── UPDATE ──────────────────────────────────────────────────────────────

    def update(self, did: str, updater, *, proof_key: Optional[KeyPair] = None) -> DIDResolutionResult:
        doc = self._registry.get(did)
        if doc is None:
            return DIDResolutionResult(did=did, error="notFound")
        updater(doc)
        doc.updated = datetime.now(timezone.utc)
        doc.version_id = str(int(doc.version_id) + 1)
        return DIDResolutionResult(did=did, document=doc)

    # ── DEACTIVATE ──────────────────────────────────────────────────────────

    def deactivate(self, did: str) -> bool:
        doc = self._registry.get(did)
        if doc is None:
            return False
        doc.deactivated = True
        doc.updated = datetime.now(timezone.utc)
        return True
