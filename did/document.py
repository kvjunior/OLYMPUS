"""
OLYMPUS DID Document — W3C DID Core v1.0 with OLYMPUS Extensions.

OLYMPUS-specific extensions (under ``olympus`` namespace):
    agentType, autonomyLevel, capabilities, delegationChain, worldBindings.

References:
    [1] W3C DID Core v1.0  — https://www.w3.org/TR/did-core/
    [2] W3C DID Resolution — https://w3c-ccg.github.io/did-resolution/
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone
import json, copy

from olympus.core.types import (
    DIDType, AgentType, AutonomyLevel, WorldType,
)
from olympus.crypto.primitives import KeyPair, sha256

DID_CONTEXT_V1          = "https://www.w3.org/ns/did/v1"
DID_CONTEXT_SECURITY_V2 = "https://w3id.org/security/suites/ed25519-2020/v1"
DID_CONTEXT_BBS         = "https://w3id.org/security/bbs/v1"
OLYMPUS_CONTEXT         = "https://olympus.id/ns/v1"


@dataclass
class VerificationMethod:
    id: str
    type: str
    controller: str
    public_key_multibase: Optional[str] = None
    public_key_jwk:       Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        r: Dict[str, Any] = {"id": self.id, "type": self.type, "controller": self.controller}
        if self.public_key_multibase:
            r["publicKeyMultibase"] = self.public_key_multibase
        elif self.public_key_jwk:
            r["publicKeyJwk"] = self.public_key_jwk
        return r

    @classmethod
    def from_key_pair(cls, kp: KeyPair, controller: str) -> VerificationMethod:
        return cls(
            id=f"{controller}#{kp.key_id}", type=kp.key_type,
            controller=controller, public_key_multibase=kp.public_key_multibase(),
        )

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> VerificationMethod:
        return cls(id=d["id"], type=d["type"], controller=d["controller"],
                   public_key_multibase=d.get("publicKeyMultibase"),
                   public_key_jwk=d.get("publicKeyJwk"))


@dataclass
class ServiceEndpoint:
    id: str; type: str
    service_endpoint: Union[str, Dict[str, Any], List[str]]
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        r = {"id": self.id, "type": self.type, "serviceEndpoint": self.service_endpoint}
        if self.description:
            r["description"] = self.description
        return r

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> ServiceEndpoint:
        return cls(d["id"], d["type"], d["serviceEndpoint"], d.get("description"))


@dataclass
class DIDDocument:
    """W3C DID Document with OLYMPUS extensions for Quaternary World Model."""

    id: str
    controller:             List[str]                      = field(default_factory=list)
    verification_method:    List[VerificationMethod]        = field(default_factory=list)
    authentication:         List[Union[str, VerificationMethod]] = field(default_factory=list)
    assertion_method:       List[Union[str, VerificationMethod]] = field(default_factory=list)
    key_agreement:          List[Union[str, VerificationMethod]] = field(default_factory=list)
    capability_invocation:  List[Union[str, VerificationMethod]] = field(default_factory=list)
    capability_delegation:  List[Union[str, VerificationMethod]] = field(default_factory=list)
    service:                List[ServiceEndpoint]           = field(default_factory=list)
    also_known_as:          List[str]                       = field(default_factory=list)

    # OLYMPUS agent extensions
    agent_type:       Optional[AgentType]     = None
    autonomy_level:   Optional[AutonomyLevel] = None
    capabilities:     List[str]               = field(default_factory=list)
    delegation_chain: List[str]               = field(default_factory=list)
    world_bindings:   Dict[str, str]          = field(default_factory=dict)

    # Metadata
    created:      datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated:      datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version_id:   str  = "1"
    deactivated:  bool = False

    def __post_init__(self):
        if not self.controller:
            self.controller = [self.id]

    @property
    def did_type(self) -> DIDType:
        parts = self.id.split(":")
        if len(parts) >= 3 and parts[:2] == ["did", "olympus"]:
            return DIDType(parts[2])
        raise ValueError(f"Invalid OLYMPUS DID: {self.id}")

    @property
    def world(self) -> WorldType:
        return self.did_type.world

    @property
    def context(self) -> List[str]:
        ctx = [DID_CONTEXT_V1, DID_CONTEXT_SECURITY_V2]
        has_bbs = any(vm.type.startswith("Bls") for vm in self.verification_method)
        if has_bbs:
            ctx.append(DID_CONTEXT_BBS)
        if self.agent_type or self.world_bindings:
            ctx.append(OLYMPUS_CONTEXT)
        return ctx

    def get_verification_method(self, kid: str) -> Optional[VerificationMethod]:
        for vm in self.verification_method:
            if vm.id == kid:
                return vm
        return None

    def compute_hash(self) -> str:
        d = self.to_dict(); d.pop("proof", None)
        return sha256(json.dumps(d, sort_keys=True, default=str).encode()).hex()

    # ── Serialisation ───────────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            "@context": self.context, "id": self.id, "controller": self.controller,
        }
        if self.also_known_as:
            doc["alsoKnownAs"] = self.also_known_as
        if self.verification_method:
            doc["verificationMethod"] = [vm.to_dict() for vm in self.verification_method]
        for key, attr in [
            ("authentication", self.authentication),
            ("assertionMethod", self.assertion_method),
            ("keyAgreement", self.key_agreement),
            ("capabilityInvocation", self.capability_invocation),
            ("capabilityDelegation", self.capability_delegation),
        ]:
            if attr:
                doc[key] = [a if isinstance(a, str) else a.to_dict() for a in attr]
        if self.service:
            doc["service"] = [s.to_dict() for s in self.service]
        # OLYMPUS extensions
        if self.agent_type or self.autonomy_level is not None or self.world_bindings:
            ext: Dict[str, Any] = {}
            if self.agent_type:
                ext["agentType"] = self.agent_type.value
            if self.autonomy_level is not None:
                ext["autonomyLevel"] = self.autonomy_level.value
            if self.capabilities:
                ext["capabilities"] = self.capabilities
            if self.delegation_chain:
                ext["delegationChain"] = self.delegation_chain
            if self.world_bindings:
                ext["worldBindings"] = self.world_bindings
            doc["olympus"] = ext
        return doc

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> DIDDocument:
        ctrl = d.get("controller", [])
        if isinstance(ctrl, str):
            ctrl = [ctrl]
        vms = [VerificationMethod.from_dict(v) for v in d.get("verificationMethod", [])]
        svcs = [ServiceEndpoint.from_dict(s) for s in d.get("service", [])]
        ext = d.get("olympus", {})
        at = AgentType(ext["agentType"]) if "agentType" in ext else None
        al = AutonomyLevel(ext["autonomyLevel"]) if "autonomyLevel" in ext else None
        return cls(
            id=d["id"], controller=ctrl, verification_method=vms,
            authentication=d.get("authentication", []),
            assertion_method=d.get("assertionMethod", []),
            key_agreement=d.get("keyAgreement", []),
            capability_invocation=d.get("capabilityInvocation", []),
            capability_delegation=d.get("capabilityDelegation", []),
            service=svcs, also_known_as=d.get("alsoKnownAs", []),
            agent_type=at, autonomy_level=al,
            capabilities=ext.get("capabilities", []),
            delegation_chain=ext.get("delegationChain", []),
            world_bindings=ext.get("worldBindings", {}),
        )


class DIDDocumentBuilder:
    """Fluent builder for DID Documents."""

    def __init__(self, did: str):
        self._did = did
        self._ctrl: List[str] = [did]
        self._vms: List[VerificationMethod] = []
        self._auth: List[str] = []
        self._assert: List[str] = []
        self._svcs: List[ServiceEndpoint] = []
        self._at: Optional[AgentType] = None
        self._al: Optional[AutonomyLevel] = None
        self._caps: List[str] = []
        self._del_chain: List[str] = []
        self._bindings: Dict[str, str] = {}

    def add_controller(self, did: str):
        if did not in self._ctrl: self._ctrl.append(did)
        return self

    def add_key(self, kp: KeyPair):
        self._vms.append(VerificationMethod.from_key_pair(kp, self._did))
        return self

    def set_authentication(self, kid: Optional[str] = None):
        self._auth.append(kid or (self._vms[0].id if self._vms else ""))
        return self

    def set_assertion_method(self, kid: Optional[str] = None):
        self._assert.append(kid or (self._vms[0].id if self._vms else ""))
        return self

    def add_service(self, sid: str, stype: str, endpoint):
        self._svcs.append(ServiceEndpoint(f"{self._did}#{sid}", stype, endpoint))
        return self

    def set_agent_properties(self, at: AgentType, al: AutonomyLevel, caps=None):
        self._at, self._al = at, al
        if caps: self._caps = caps
        return self

    def add_delegation(self, owner_did: str):
        self._del_chain.append(owner_did)
        if owner_did not in self._ctrl: self._ctrl.append(owner_did)
        return self

    def add_world_binding(self, world: WorldType, did: str):
        self._bindings[world.value] = did
        return self

    def build(self) -> DIDDocument:
        return DIDDocument(
            id=self._did, controller=self._ctrl,
            verification_method=self._vms,
            authentication=self._auth, assertion_method=self._assert,
            service=self._svcs, agent_type=self._at, autonomy_level=self._al,
            capabilities=self._caps, delegation_chain=self._del_chain,
            world_bindings=self._bindings,
        )
