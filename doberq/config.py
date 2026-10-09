"""DoberQ configuration dataclass."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DoberQConfig:
    kem_algorithm: str = "ML-KEM-768"
    sig_algorithm: str = "ML-DSA-65"
    key_dir: str = "doberq/keys"
    relay_host: Optional[str] = None
    relay_port: int = 9443
    relay_timeout_s: float = 0.5
    skip_blocked: bool = True
    dry_run: bool = False
    benchmark_mode: bool = False

    SUPPORTED_KEM = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
    SUPPORTED_SIG = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")

    def __post_init__(self) -> None:
        if self.kem_algorithm not in self.SUPPORTED_KEM:
            raise ValueError(
                f"Unsupported KEM algorithm '{self.kem_algorithm}'. "
                f"Choose from: {self.SUPPORTED_KEM}"
            )
        if self.sig_algorithm not in self.SUPPORTED_SIG:
            raise ValueError(
                f"Unsupported signature algorithm '{self.sig_algorithm}'. "
                f"Choose from: {self.SUPPORTED_SIG}"
            )
