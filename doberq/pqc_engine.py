"""
PQCEngine — liboqs wrappers for NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).

All operations run on classical x86_64/ARM hardware via the Open Quantum Safe
liboqs C library. No quantum hardware is required or assumed.

Requires: pip install oqs
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time

import oqs  # liboqs-python

from .capsule import DoberQCapsule

logger = logging.getLogger("doberq.pqc_engine")

# HKDF info string used when deriving AES-256 key from KEM shared secret
_HKDF_INFO = b"DoberQ-AES256GCM-v1"
_AES_KEY_LEN = 32   # bytes → AES-256
_GCM_NONCE_LEN = 12  # bytes


class PQCEngine:
    """
    Classical-hardware implementation of NIST PQC primitives.

    Wraps oqs.KeyEncapsulation (ML-KEM) and oqs.Signature (ML-DSA) with a
    clean interface matching the DoberQ architecture specification.
    """

    def __init__(
        self,
        kem_alg: str = "ML-KEM-768",
        sig_alg: str = "ML-DSA-65",
    ) -> None:
        self.kem_alg = kem_alg
        self.sig_alg = sig_alg
        # Probe the algorithms on construction to surface missing support early.
        with oqs.KeyEncapsulation(kem_alg) as kem:
            self._kem_pk_len = kem.details["length_public_key"]
            self._kem_ct_len = kem.details["length_ciphertext"]
        with oqs.Signature(sig_alg) as sig:
            self._sig_pk_len = sig.details["length_public_key"]
            self._sig_sig_len = sig.details["length_signature"]
        logger.debug(
            "PQCEngine ready: KEM=%s (pk=%d ct=%d) SIG=%s (pk=%d sig=%d)",
            kem_alg, self._kem_pk_len, self._kem_ct_len,
            sig_alg, self._sig_pk_len, self._sig_sig_len,
        )

    # =========================================================================
    # Key Encapsulation Mechanism (FIPS 203 — ML-KEM)
    # =========================================================================

    def generate_kem_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key). Share pk with the backbone."""
        with oqs.KeyEncapsulation(self.kem_alg) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return pk, sk

    def encapsulate(self, recipient_pk: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret). Send ciphertext to recipient."""
        with oqs.KeyEncapsulation(self.kem_alg) as kem:
            ciphertext, shared_secret = kem.encap_secret(recipient_pk)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, sk: bytes) -> bytes:
        """Return shared_secret. Called by the backbone on capsule receipt."""
        with oqs.KeyEncapsulation(self.kem_alg, sk) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    # =========================================================================
    # Digital Signatures (FIPS 204 — ML-DSA)
    # =========================================================================

    def generate_sig_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key). Publish pk to backbone verifiers."""
        with oqs.Signature(self.sig_alg) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return pk, sk

    def sign(self, message: bytes, sk: bytes) -> bytes:
        """Return ML-DSA signature over message using secret_key."""
        with oqs.Signature(self.sig_alg, sk) as sig:
            return sig.sign(message)

    def verify(self, message: bytes, signature: bytes, pk: bytes) -> bool:
        """Return True if signature is valid under public_key."""
        with oqs.Signature(self.sig_alg) as sig:
            return sig.verify(message, signature, pk)

    # =========================================================================
    # AES-256-GCM helpers
    # =========================================================================

    def derive_aes_key(self, shared_secret: bytes) -> bytes:
        """HKDF-SHA256(shared_secret) → 32-byte AES-256 key."""
        # Simplified HKDF: Extract (HMAC-SHA256 with zero salt) → Expand
        salt = b"\x00" * 32
        prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()
        okm = hmac.new(prk, _HKDF_INFO + b"\x01", hashlib.sha256).digest()
        return okm[:_AES_KEY_LEN]

    def aes_gcm_encrypt(
        self, key: bytes, plaintext: bytes
    ) -> tuple[bytes, bytes]:
        """Return (nonce, ciphertext_with_tag). nonce is 12 random bytes."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(_GCM_NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return nonce, ct

    def aes_gcm_decrypt(
        self, key: bytes, nonce: bytes, ciphertext_with_tag: bytes
    ) -> bytes:
        """Return plaintext. Raises cryptography.exceptions.InvalidTag on failure."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, ciphertext_with_tag, None)

    # =========================================================================
    # Convenience: one-shot flow wrapping
    # =========================================================================

    def wrap_flow(
        self,
        flow_json: bytes,
        recipient_kem_pk: bytes,
        gateway_sig_sk: bytes,
    ) -> DoberQCapsule:
        """
        Full PQC encapsulation pipeline:
          1. ML-KEM: encapsulate shared secret under recipient's public key
          2. HKDF: derive 32-byte AES-256 key from shared secret
          3. AES-256-GCM: encrypt flow_json
          4. ML-DSA: sign (kem_ciphertext ‖ nonce ‖ encrypted_payload)
          5. Return populated DoberQCapsule
        """
        # Step 1: KEM
        kem_ct, shared_secret = self.encapsulate(recipient_kem_pk)

        # Step 2: Key derivation
        aes_key = self.derive_aes_key(shared_secret)

        # Step 3: Encryption
        nonce, encrypted_payload = self.aes_gcm_encrypt(aes_key, flow_json)

        # Step 4: Build capsule (partial) to compute signed blob
        capsule = DoberQCapsule(
            kem_alg=self.kem_alg,
            sig_alg=self.sig_alg,
            kem_ciphertext=kem_ct,
            nonce=nonce,
            encrypted_payload=encrypted_payload,
        )

        # Step 5: Sign
        capsule.signature = self.sign(capsule.signed_blob, gateway_sig_sk)

        return capsule

    def unwrap_flow(
        self,
        capsule: DoberQCapsule,
        recipient_kem_sk: bytes,
        gateway_sig_pk: bytes,
    ) -> bytes:
        """
        Reverse pipeline (for backbone receiver or unit tests):
          1. ML-DSA: verify signature
          2. ML-KEM: decapsulate shared secret
          3. HKDF: derive AES key
          4. AES-256-GCM: decrypt payload
          5. Return plaintext flow_json bytes
        """
        if not self.verify(capsule.signed_blob, capsule.signature, gateway_sig_pk):
            raise ValueError("DoberQCapsule signature verification failed")

        shared_secret = self.decapsulate(capsule.kem_ciphertext, recipient_kem_sk)
        aes_key = self.derive_aes_key(shared_secret)
        return self.aes_gcm_decrypt(aes_key, capsule.nonce, capsule.encrypted_payload)

    # =========================================================================
    # Introspection
    # =========================================================================

    @property
    def kem_public_key_bytes(self) -> int:
        return self._kem_pk_len

    @property
    def kem_ciphertext_bytes(self) -> int:
        return self._kem_ct_len

    @property
    def sig_public_key_bytes(self) -> int:
        return self._sig_pk_len

    @property
    def sig_signature_bytes(self) -> int:
        return self._sig_sig_len

    @staticmethod
    def supported_kem_algorithms() -> list[str]:
        return oqs.get_enabled_kem_mechanisms()

    @staticmethod
    def supported_sig_algorithms() -> list[str]:
        return oqs.get_enabled_sig_mechanisms()
