"""KeyStore — PQC keypair lifecycle management."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .pqc_engine import PQCEngine

logger = logging.getLogger("doberq.key_store")

_KEY_FILES = {
    "kem_pk": "kem_public.key",
    "kem_sk": "kem_secret.key",
    "sig_pk": "sig_public.key",
    "sig_sk": "sig_secret.key",
    "backbone_kem_pk": "backbone_kem_pub.key",
}


class KeyStore:
    """
    Manages PQC keypair lifecycle: generation, persistence, and loading.

    Keys are stored as raw binary files under key_dir/.  The gateway's
    KEM/DSA keypairs are generated once and reused across restarts.
    The backbone's KEM public key must be deposited into key_dir/ as
    backbone_kem_pub.key out-of-band (or via --pqc-relay-host provisioning).

    When backbone_kem_pub.key is absent (first-run or standalone mode),
    the gateway uses its own KEM public key as the recipient — enabling
    self-encapsulation for benchmarking and dry-run testing.
    """

    def __init__(self, key_dir: str, engine: "PQCEngine") -> None:
        self._dir = Path(key_dir)
        self._engine = engine
        self._keys: dict[str, bytes] = {}

    def load_or_generate(self) -> dict[str, bytes]:
        """Load existing keypairs; generate and persist if absent."""
        self._dir.mkdir(parents=True, exist_ok=True)

        kem_pk_path = self._dir / _KEY_FILES["kem_pk"]
        kem_sk_path = self._dir / _KEY_FILES["kem_sk"]
        sig_pk_path = self._dir / _KEY_FILES["sig_pk"]
        sig_sk_path = self._dir / _KEY_FILES["sig_sk"]

        if kem_pk_path.exists() and kem_sk_path.exists():
            kem_pk = kem_pk_path.read_bytes()
            kem_sk = kem_sk_path.read_bytes()
            logger.info("Loaded existing KEM keypair from %s", self._dir)
        else:
            kem_pk, kem_sk = self._engine.generate_kem_keypair()
            kem_pk_path.write_bytes(kem_pk)
            kem_sk_path.write_bytes(kem_sk)
            _secure_permissions(kem_sk_path)
            logger.info(
                "Generated new %s keypair → %s",
                self._engine.kem_alg, self._dir
            )

        if sig_pk_path.exists() and sig_sk_path.exists():
            sig_pk = sig_pk_path.read_bytes()
            sig_sk = sig_sk_path.read_bytes()
            logger.info("Loaded existing DSA keypair from %s", self._dir)
        else:
            sig_pk, sig_sk = self._engine.generate_sig_keypair()
            sig_pk_path.write_bytes(sig_pk)
            sig_sk_path.write_bytes(sig_sk)
            _secure_permissions(sig_sk_path)
            logger.info(
                "Generated new %s keypair → %s",
                self._engine.sig_alg, self._dir
            )

        # Backbone KEM public key — fall back to self-encap if absent
        backbone_pk_path = self._dir / _KEY_FILES["backbone_kem_pk"]
        if backbone_pk_path.exists():
            backbone_kem_pk = backbone_pk_path.read_bytes()
            logger.info("Loaded backbone KEM public key from %s", backbone_pk_path)
        else:
            backbone_kem_pk = kem_pk
            logger.warning(
                "backbone_kem_pub.key not found in %s — using gateway's own "
                "KEM public key for self-encapsulation (dry-run / benchmark mode).",
                self._dir,
            )

        self._keys = {
            "kem_pk": kem_pk,
            "kem_sk": kem_sk,
            "sig_pk": sig_pk,
            "sig_sk": sig_sk,
            "backbone_kem_pk": backbone_kem_pk,
        }
        return self._keys

    def get_backbone_kem_pk(self) -> bytes:
        if not self._keys:
            raise RuntimeError("KeyStore not initialized — call load_or_generate() first")
        return self._keys["backbone_kem_pk"]

    def rotate_kem_keypair(self) -> tuple[bytes, bytes]:
        """Generate a fresh KEM keypair and overwrite persisted files."""
        kem_pk, kem_sk = self._engine.generate_kem_keypair()
        (self._dir / _KEY_FILES["kem_pk"]).write_bytes(kem_pk)
        sk_path = self._dir / _KEY_FILES["kem_sk"]
        sk_path.write_bytes(kem_sk)
        _secure_permissions(sk_path)
        self._keys["kem_pk"] = kem_pk
        self._keys["kem_sk"] = kem_sk
        logger.info("KEM keypair rotated")
        return kem_pk, kem_sk


def _secure_permissions(path: Path) -> None:
    """Restrict secret key file to owner-read-only (chmod 600)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Non-POSIX or permission denied — best-effort
