"""V2 construction boundary."""
from dataclasses import dataclass
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.hooks.registry import HookRegistry
from aicomp_sdk.hooks.types import HookStage
from .successful_read_ledger_v2 import SuccessfulReadLedgerV2
from .trusted_read_outcome_hook_v2 import TrustedReadOutcomeHookV2
from .lineage_aware_exfil_guardrail_v2 import LineageAwareExfilGuardrailV2
@dataclass(frozen=True, slots=True)
class ExfilIntegrationBundleV2:
    ledger: SuccessfulReadLedgerV2
    hook: TrustedReadOutcomeHookV2
    guardrail: LineageAwareExfilGuardrailV2
class ExfilIntegrationFactoryV2:
    @staticmethod
    def build(*, hook_registry: HookRegistry, inner: GuardrailBase | None=None, priority: int=0) -> ExfilIntegrationBundleV2:
        ledger=SuccessfulReadLedgerV2(); hook=TrustedReadOutcomeHookV2(ledger=ledger); guardrail=LineageAwareExfilGuardrailV2(ledger=ledger,inner=inner)
        hook_registry.register_hook(HookStage.POST_TOOL_CALL,hook,priority)
        return ExfilIntegrationBundleV2(ledger=ledger,hook=hook,guardrail=guardrail)
def build_exfil_integration_v2(*, hook_registry: HookRegistry, inner: GuardrailBase | None=None, priority: int=0) -> ExfilIntegrationBundleV2:
    return ExfilIntegrationFactoryV2.build(hook_registry=hook_registry,inner=inner,priority=priority)
