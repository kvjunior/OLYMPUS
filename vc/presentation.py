"""
OLYMPUS Verifiable Presentations — W3C VP with domain binding and replay protection.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timezone
import json, uuid

from olympus.vc.credential import VerifiableCredential, CredentialProof, CredentialIssuer
from olympus.crypto.primitives import KeyPair, Ed25519KeyGenerator, sha256


@dataclass
class VerifiablePresentation:
    id: str
    type: List[str] = field(default_factory=lambda: ["VerifiablePresentation"])
    holder: Optional[str] = None
    verifiable_credential: List[VerifiableCredential] = field(default_factory=list)
    proof: Optional[Union[CredentialProof, List[CredentialProof]]] = None
    metaverse_context: Optional[str] = None
    presentation_purpose: Optional[str] = None
    selective_disclosure: Dict[str, List[str]] = field(default_factory=dict)

    def add_credential(self, vc: VerifiableCredential):
        self.verifiable_credential.append(vc)

    def compute_hash(self) -> str:
        d = self.to_dict(); d.pop("proof", None)
        return sha256(json.dumps(d, sort_keys=True, default=str).encode()).hex()

    def to_dict(self) -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            "@context": ["https://www.w3.org/ns/credentials/v2",
                         "https://olympus.id/ns/presentations/v1"],
            "id": self.id, "type": self.type,
        }
        if self.holder: doc["holder"] = self.holder
        if self.verifiable_credential:
            doc["verifiableCredential"] = [vc.to_dict() for vc in self.verifiable_credential]
        if self.proof:
            if isinstance(self.proof, list):
                doc["proof"] = [p.to_dict() for p in self.proof]
            else:
                doc["proof"] = self.proof.to_dict()
        if self.metaverse_context or self.selective_disclosure:
            doc["olympus"] = {}
            if self.metaverse_context: doc["olympus"]["metaverseContext"] = self.metaverse_context
            if self.selective_disclosure: doc["olympus"]["selectiveDisclosure"] = self.selective_disclosure
        return doc

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> VerifiablePresentation:
        creds = [VerifiableCredential.from_dict(v) for v in d.get("verifiableCredential", [])]
        proof = None
        if "proof" in d:
            pd = d["proof"]
            proof = ([CredentialProof.from_dict(p) for p in pd] if isinstance(pd, list)
                     else CredentialProof.from_dict(pd))
        ext = d.get("olympus", {})
        return cls(
            id=d["id"], type=d.get("type", ["VerifiablePresentation"]),
            holder=d.get("holder"), verifiable_credential=creds, proof=proof,
            metaverse_context=ext.get("metaverseContext"),
            selective_disclosure=ext.get("selectiveDisclosure", {}),
        )


class PresentationSigner:
    def __init__(self, holder_did: str, signing_key: KeyPair):
        self.holder_did = holder_did
        self.key = signing_key
        self._gen = Ed25519KeyGenerator()

    def sign(self, vp: VerifiablePresentation, *,
             challenge: Optional[str] = None, domain: Optional[str] = None) -> VerifiablePresentation:
        if vp.holder is None:
            vp.holder = self.holder_did
        h = vp.compute_hash()
        payload = h.encode()
        if challenge: payload += challenge.encode()
        if domain: payload += domain.encode()
        sig = self._gen.sign(self.key.private_key, payload)
        vp.proof = CredentialProof(
            type="Ed25519Signature2020", created=datetime.now(timezone.utc),
            verification_method=f"{self.holder_did}#{self.key.key_id}",
            proof_purpose="authentication", proof_value="z" + sig.hex(),
            challenge=challenge, domain=domain,
        )
        return vp


class PresentationVerifier:
    def __init__(self, issuer: Optional[CredentialIssuer] = None):
        self.issuer = issuer
        self._gen = Ed25519KeyGenerator()

    def verify(self, vp: VerifiablePresentation, *,
               expected_challenge: Optional[str] = None,
               expected_domain: Optional[str] = None,
               holder_public_key: Optional[bytes] = None) -> tuple[bool, List[str]]:
        errors: List[str] = []
        if vp.proof is None:
            return False, ["Missing proof"]
        p = vp.proof if isinstance(vp.proof, CredentialProof) else vp.proof[0]
        if expected_challenge and p.challenge != expected_challenge:
            errors.append("Challenge mismatch")
        if expected_domain and p.domain != expected_domain:
            errors.append("Domain mismatch")
        # Verify holder signature
        if holder_public_key:
            h = vp.compute_hash()
            payload = h.encode()
            if p.challenge: payload += p.challenge.encode()
            if p.domain: payload += p.domain.encode()
            sig_hex = p.proof_value[1:] if p.proof_value.startswith("z") else p.proof_value
            try:
                if not self._gen.verify(holder_public_key, payload, bytes.fromhex(sig_hex)):
                    errors.append("Invalid holder signature")
            except Exception as e:
                errors.append(f"Signature error: {e}")
        # Verify each credential
        if self.issuer:
            for vc in vp.verifiable_credential:
                ok, errs = self.issuer.verify(vc)
                if not ok:
                    errors.extend(errs)
        # Holder binding
        if vp.holder and vp.verifiable_credential:
            if not any(vc.subject_id == vp.holder for vc in vp.verifiable_credential):
                errors.append("No credential matches holder")
        return len(errors) == 0, errors
