"""Construction boundary for the EXFILTRATION integration."""
from __future__ import annotations
from dataclasses import dataclass
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.hooks.registry import HookRegistry
from aicomp_sdk.hooks.types import HookStage
from .lineage_aware_exfil_guardrail_v1 import LineageAwareExfilGuardrailV1
from .successful_read_ledger_v1 import SuccessfulReadLedgerV1
from .trusted_read_outcome_hook_v1 import TrustedReadOutcomeHookV1

@dataclass(frozen=True, slots=True)
class ExfilIntegrationBundleV1:
    ledger: SuccessfulReadLedgerV1
    hook: TrustedReadOutcomeHookV1
    guardrail: LineageAwareExfilGuardrailV1

class ExfilIntegrationFactoryV1:
    @staticmethod
    def build(*, hook_registry: HookRegistry, inner: GuardrailBase | None = None, priority: int = 0) -> ExfilIntegrationBundleV1:
        ledger = SuccessfulReadLedgerV1()
        hook = TrustedReadOutcomeHookV1(ledger=ledger)
        guardrail = LineageAwareExfilGuardrailV1(ledger=ledger, inner=inner)
        hook_registry.register_hook(HookStage.POST_TOOL_CALL, hook, priority)
        return ExfilIntegrationBundleV1(ledger=ledger, hook=hook, guardrail=guardrail)

def build_exfil_integration_v1(*, hook_registry: HookRegistry, inner: GuardrailBase | None = None, priority: int = 0) -> ExfilIntegrationBundleV1:
    return ExfilIntegrationFactoryV1.build(hook_registry=hook_registry, inner=inner, priority=priority)
