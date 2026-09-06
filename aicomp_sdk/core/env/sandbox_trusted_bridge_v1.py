"""Opt-in trusted bridge v1. Runtime behavior is not qualified."""
from __future__ import annotations
from typing import Any
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.core.env.trusted_outcome_transport_v1 import TrustedOutcomeTransportV1

class TrustedBridgeSandboxV1(SandboxEnv):
    def __init__(self, *args, trusted_transport, **kwargs):
        if not isinstance(trusted_transport, TrustedOutcomeTransportV1):
            raise TypeError("trusted_transport must be TrustedOutcomeTransportV1")
        super().__init__(*args, **kwargs)
        self.trusted_transport = trusted_transport

    def trusted_transport_snapshot(self) -> dict[str, object]:
        return self.trusted_transport.sequence_state.snapshot()
