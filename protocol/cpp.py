"""
OLYMPUS Credential Portability Protocol (CPP)
==============================================
Cross-chain credential transfer with schema translation and re-anchoring.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
from enum import Enum
import secrets, hashlib, json

from olympus.crypto.primitives import sha256, Ed25519KeyGenerator, KeyPair


class VDRType(Enum):
    ETHEREUM = "ethereum"; POLYGON = "polygon"; IOTA = "iota"
    ION = "ion"; OLYMPUS = "olympus"; CUSTOM = "custom"


@dataclass
class PortableCredential:
    id: str
    original: Dict[str, Any]
    source_vdr: VDRType
    issuer_did: str = ""
    subject_did: str = ""
    export_proof: bytes = b""
    anchors: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def wrap(cls, cred: Dict[str, Any], vdr: VDRType) -> PortableCredential:
        return cls(
            id=f"port-{secrets.token_hex(12)}", original=cred, source_vdr=vdr,
            issuer_did=cred.get("issuer", ""),
            subject_did=cred.get("credentialSubject", {}).get("id", ""),
        )


@dataclass
class SchemaMapping:
    source: str; target: str
    field_map: Dict[str, str]

    def translate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {self.field_map[k]: data[k] for k in self.field_map if k in data}


class CredentialPortabilityProtocol:
    def __init__(self):
        self._gen = Ed25519KeyGenerator()
        self.mappings: Dict[Tuple[str, str], SchemaMapping] = {}
        # Register defaults
        self.register_mapping(SchemaMapping(
            "AvatarGenesisCredential", "AvatarIdentityCredential",
            {"avatarDID": "avatar_id", "humanIdentityHash": "owner_hash"},
        ))

    def register_mapping(self, m: SchemaMapping):
        self.mappings[(m.source, m.target)] = m

    def export_credential(self, cred: Dict[str, Any], vdr: VDRType,
                          signing_key: KeyPair) -> PortableCredential:
        pc = PortableCredential.wrap(cred, vdr)
        digest = sha256(json.dumps(cred, sort_keys=True).encode())
        pc.export_proof = self._gen.sign(signing_key.private_key, digest)
        return pc

    def verify_export(self, pc: PortableCredential, pk: bytes) -> bool:
        digest = sha256(json.dumps(pc.original, sort_keys=True).encode())
        return self._gen.verify(pk, digest, pc.export_proof)

    def import_credential(self, pc: PortableCredential, pk: bytes,
                          target_schema: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        if not self.verify_export(pc, pk):
            return False, {"error": "Invalid export proof"}
        result = pc.original.copy()
        if target_schema:
            ctype = pc.original.get("type", [""])[0] if pc.original.get("type") else ""
            m = self.mappings.get((ctype, target_schema))
            if m:
                subj = result.get("credentialSubject", {})
                result["credentialSubject"] = m.translate(subj)
                result["type"] = [target_schema]
        return True, result
