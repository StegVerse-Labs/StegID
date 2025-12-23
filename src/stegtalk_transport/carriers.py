from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Protocol


@dataclass(frozen=True)
class CarrierCaps:
    """
    Capability metadata for routing decisions.
    """
    name: str
    max_payload_bytes: int
    supports_broadcast: bool
    supports_bidirectional: bool
    typical_latency_ms: int


class Carrier(Protocol):
    """
    A carrier moves opaque bytes. It does not interpret them.

    Implementations may use BLE, NFC, QR, audio, optical, etc.
    """
    def caps(self) -> CarrierCaps: ...

    def send(self, payload: bytes) -> None:
        """
        Best-effort send. Implementations should never crash the caller.
        """
        ...

    def receive(self) -> Optional[bytes]:
        """
        Best-effort receive. Returns payload bytes or None.
        """
        ...


class CarrierRegistry:
    def __init__(self) -> None:
        self._carriers: Dict[str, Carrier] = {}

    def register(self, name: str, carrier: Carrier) -> None:
        self._carriers[name] = carrier

    def get(self, name: str) -> Optional[Carrier]:
        return self._carriers.get(name)

    def list(self) -> Dict[str, Carrier]:
        return dict(self._carriers)
