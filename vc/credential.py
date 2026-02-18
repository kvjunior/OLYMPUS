"""
OLYMPUS Verifiable Credentials — W3C VC Data Model 2.0 with real signatures.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timezone
import json, uuid

from olympus.crypto.primitives import KeyPair, Ed25519KeyGenerator, sha256

VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
OLYMPUS_VC_CONTEXT = "https://olympus.id/ns/credentials/v1"


@dataclass
class CredentialProof:
    type: str
    created: datetime
    verification_method: str
    proof_purpose: str
    proof_value: str
    challenge: Optional[str] = None
    domain: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "type": self.type, "created": self.created.isoformat(),
            "verificationMethod": self.verification_method,
            "proofPurpose": self.proof_purpose, "proofValue": self.proof_value,
        }
        if self.challenge: d["challenge"] = self.challenge
        if self.domain: d["domain"] = self.domain
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CredentialProof:
        return cls(
            type=d["type"],
            created=datetime.fromisoformat(d["created"]) if isinstance(d["created"], str) else d["created"],
            verification_method=d["verificationMethod"],
            proof_purpose=d["proofPurpose"], proof_value=d["proofValue"],
            challenge=d.get("challenge"), domain=d.get("domain"),
        )


@dataclass
class VerifiableCredential:
    id: str
    type: List[str]
    issuer: str
    issuance_date: datetime
    subject_id: str
    subject_claims: Dict[str, Any]
    expiration_date: Optional[datetime] = None
    credential_status: Optional[Dict[str, Any]] = None
    proof: Optional[CredentialProof] = None

    @property
    def context(self) -> List[str]:
        return [VC_CONTEXT, OLYMPUS_VC_CONTEXT]

    def canonical_bytes(self) -> bytes:
        d = self.to_dict()
        d.pop("proof", None)
        return json.dumps(d, sort_keys=True, default=str).encode()

    def digest(self) -> bytes:
        return sha256(self.canonical_bytes())

    def to_dict(self) -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            "@context": self.context, "id": self.id, "type": self.type,
            "issuer": self.issuer, "issuanceDate": self.issuance_date.isoformat(),
            "credentialSubject": {"id": self.subject_id, **self.subject_claims},
        }
        if self.expiration_date:
            doc["expirationDate"] = self.expiration_date.isoformat()
        if self.credential_status:
            doc["credentialStatus"] = self.credential_status
        if self.proof:
            doc["proof"] = self.proof.to_dict()
        return doc

    def to_json(self, indent=2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> VerifiableCredential:
        subj = d.get("credentialSubject", {})
        sid = subj.pop("id", "")
        proof = CredentialProof.from_dict(d["proof"]) if "proof" in d else None
        iso = d.get("issuanceDate", "")
        return cls(
            id=d["id"], type=d.get("type", ["VerifiableCredential"]),
            issuer=d.get("issuer", ""),
            issuance_date=datetime.fromisoformat(iso) if isinstance(iso, str) else iso,
            subject_id=sid, subject_claims=subj,
            expiration_date=datetime.fromisoformat(d["expirationDate"]) if "expirationDate" in d else None,
            credential_status=d.get("credentialStatus"), proof=proof,
        )


class CredentialIssuer:
    """Issues VCs with real Ed25519 signatures."""

    def __init__(self, issuer_did: str, signing_key: KeyPair):
        self.issuer_did = issuer_did
        self.signing_key = signing_key
        self._gen = Ed25519KeyGenerator()

    def issue(self, subject_did: str, claims: Dict[str, Any],
              credential_type: str = "OlympusCredential", *,
              expiration: Optional[datetime] = None) -> VerifiableCredential:
        vc = VerifiableCredential(
            id=f"urn:uuid:{uuid.uuid4()}", type=["VerifiableCredential", credential_type],
            issuer=self.issuer_did, issuance_date=datetime.now(timezone.utc),
            subject_id=subject_did, subject_claims=claims,
            expiration_date=expiration,
        )
        digest = vc.digest()
        sig = self._gen.sign(self.signing_key.private_key, digest)
        vc.proof = CredentialProof(
            type="Ed25519Signature2020", created=datetime.now(timezone.utc),
            verification_method=f"{self.issuer_did}#{self.signing_key.key_id}",
            proof_purpose="assertionMethod", proof_value="z" + sig.hex(),
        )
        return vc

    def verify(self, vc: VerifiableCredential) -> tuple[bool, List[str]]:
        errors: List[str] = []
        if vc.proof is None:
            return False, ["Missing proof"]
        if vc.expiration_date and datetime.now(timezone.utc) > vc.expiration_date:
            errors.append("Credential expired")
        # Verify signature
        sig_hex = vc.proof.proof_value
        if sig_hex.startswith("z"):
            sig_hex = sig_hex[1:]
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            digest = vc.digest()
            if not self._gen.verify(self.signing_key.public_key, digest, sig_bytes):
                errors.append("Invalid signature")
        except Exception as e:
            errors.append(f"Signature verification error: {e}")
        return len(errors) == 0, errors
