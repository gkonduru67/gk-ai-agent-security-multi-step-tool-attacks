"""V2.1 construction boundary."""
from dataclasses import dataclass
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.hooks.registry import HookRegistry
from aicomp_sdk.hooks.types import HookStage
from .successful_read_ledger_v2_1 import SuccessfulReadLedgerV21
from .trusted_read_outcome_hook_v2_1 import TrustedReadOutcomeHookV21
from .lineage_aware_exfil_guardrail_v2_1 import LineageAwareExfilGuardrailV21
@dataclass(frozen=True, slots=True)
class ExfilIntegrationBundleV21:
    ledger: SuccessfulReadLedgerV21
    hook: TrustedReadOutcomeHookV21
    guardrail: LineageAwareExfilGuardrailV21
class ExfilIntegrationFactoryV21:
    @staticmethod
    def build(*,hook_registry:HookRegistry,inner:GuardrailBase|None=None,priority:int=0)->ExfilIntegrationBundleV21:
        ledger=SuccessfulReadLedgerV21();hook=TrustedReadOutcomeHookV21(ledger=ledger);guardrail=LineageAwareExfilGuardrailV21(ledger=ledger,inner=inner)
        hook_registry.register_hook(HookStage.POST_TOOL_CALL,hook,priority)
        return ExfilIntegrationBundleV21(ledger=ledger,hook=hook,guardrail=guardrail)
def build_exfil_integration_v21(*,hook_registry:HookRegistry,inner:GuardrailBase|None=None,priority:int=0)->ExfilIntegrationBundleV21:
    return ExfilIntegrationFactoryV21.build(hook_registry=hook_registry,inner=inner,priority=priority)
