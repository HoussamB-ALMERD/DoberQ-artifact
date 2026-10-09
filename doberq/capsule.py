"""DoberQCapsule — PQC-wrapped flow record."""

from __future__ import annotations

import json
import struct
import time
from dataclasses import dataclass, field


# Wire format: each field preceded by a 4-byte little-endian length prefix.
# Fixed fields (version=1 byte, timestamp=8 bytes) written without prefix.
_MAGIC = b"DQ\x01"   # 3-byte magic + version


@dataclass
class DoberQCapsule:
    version: int = 1
    kem_alg: str = "ML-KEM-768"
    sig_alg: str = "ML-DSA-65"
    kem_ciphertext: bytes = b""
    nonce: bytes = b""           # 12-byte AES-GCM nonce
    encrypted_payload: bytes = b""  # AES-256-GCM ciphertext + 16-byte tag
    signature: bytes = b""       # ML-DSA signature over (ct ‖ nonce ‖ payload)
    timestamp: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize to length-prefixed binary blob."""
        def pack_bytes(b: bytes) -> bytes:
            return struct.pack("<I", len(b)) + b

        def pack_str(s: str) -> bytes:
            enc = s.encode()
            return struct.pack("<I", len(enc)) + enc

        return (
            _MAGIC
            + struct.pack("<d", self.timestamp)
            + pack_str(self.kem_alg)
            + pack_str(self.sig_alg)
            + pack_bytes(self.kem_ciphertext)
            + pack_bytes(self.nonce)
            + pack_bytes(self.encrypted_payload)
            + pack_bytes(self.signature)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "DoberQCapsule":
        """Deserialize from binary blob produced by to_bytes()."""
        if not data.startswith(_MAGIC):
            raise ValueError("Invalid DoberQCapsule magic bytes")
        pos = len(_MAGIC)

        timestamp = struct.unpack_from("<d", data, pos)[0]
        pos += 8

        def read_str() -> str:
            nonlocal pos
            length = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            value = data[pos: pos + length].decode()
            pos += length
            return value

        def read_bytes() -> bytes:
            nonlocal pos
            length = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            value = data[pos: pos + length]
            pos += length
            return value

        kem_alg = read_str()
        sig_alg = read_str()
        kem_ciphertext = read_bytes()
        nonce = read_bytes()
        encrypted_payload = read_bytes()
        signature = read_bytes()

        return cls(
            kem_alg=kem_alg,
            sig_alg=sig_alg,
            kem_ciphertext=kem_ciphertext,
            nonce=nonce,
            encrypted_payload=encrypted_payload,
            signature=signature,
            timestamp=timestamp,
        )

    def to_dict(self) -> dict:
        """JSON-serializable dict; bytes fields encoded as hex strings."""
        return {
            "version": self.version,
            "kem_alg": self.kem_alg,
            "sig_alg": self.sig_alg,
            "kem_ciphertext": self.kem_ciphertext.hex(),
            "nonce": self.nonce.hex(),
            "encrypted_payload_len": len(self.encrypted_payload),
            "signature": self.signature.hex(),
            "timestamp": self.timestamp,
            "total_bytes": self.total_bytes,
        }

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def total_bytes(self) -> int:
        return (
            len(_MAGIC) + 8  # magic + timestamp
            + 4 + len(self.kem_alg.encode())
            + 4 + len(self.sig_alg.encode())
            + 4 + len(self.kem_ciphertext)
            + 4 + len(self.nonce)
            + 4 + len(self.encrypted_payload)
            + 4 + len(self.signature)
        )

    # Bytes to sign/verify: covers ciphertext + nonce + encrypted payload
    @property
    def signed_blob(self) -> bytes:
        return self.kem_ciphertext + self.nonce + self.encrypted_payload
