"""V2.2 construction and registration boundary."""
from __future__ import annotations
from dataclasses import dataclass
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.hooks.registry import HookRegistry
from aicomp_sdk.hooks.types import HookStage
from aicomp_sdk_exfil_v2_1.successful_read_ledger_v2_1 import SuccessfulReadLedgerV21
from aicomp_sdk_exfil_v2_1.lineage_aware_exfil_guardrail_v2_1 import LineageAwareExfilGuardrailV21
from .trusted_read_proposal_hook_v2_2 import TrustedReadProposalHookV22
from .trusted_read_outcome_hook_v2_2 import TrustedReadOutcomeHookV22

DESIGN_ID_V22 = "EXFIL.V2.2.TWO_STAGE.READ.HOOK.DESIGN.1"
PROPOSAL_HOOK_PRIORITY_V22 = 0
OUTCOME_HOOK_PRIORITY_V22 = 0

@dataclass(frozen=True, slots=True)
class ExfilIntegrationBundleV22:
    ledger: SuccessfulReadLedgerV21
    proposal_hook: TrustedReadProposalHookV22
    outcome_hook: TrustedReadOutcomeHookV22
    guardrail: LineageAwareExfilGuardrailV21

class ExfilIntegrationFactoryV22:
    @staticmethod
    def build(*, hook_registry: HookRegistry, inner: GuardrailBase | None = None) -> ExfilIntegrationBundleV22:
        if not isinstance(hook_registry, HookRegistry):
            raise TypeError("hook_registry must be HookRegistry")
        ledger = SuccessfulReadLedgerV21()
        proposal_hook = TrustedReadProposalHookV22()
        outcome_hook = TrustedReadOutcomeHookV22(ledger=ledger)
        guardrail = LineageAwareExfilGuardrailV21(ledger=ledger, inner=inner)
        hook_registry.register_hook(HookStage.PRE_TOOL_CALL, proposal_hook, PROPOSAL_HOOK_PRIORITY_V22)
        hook_registry.register_hook(HookStage.POST_TOOL_CALL, outcome_hook, OUTCOME_HOOK_PRIORITY_V22)
        return ExfilIntegrationBundleV22(ledger=ledger, proposal_hook=proposal_hook, outcome_hook=outcome_hook, guardrail=guardrail)

def build_exfil_integration_v22(*, hook_registry: HookRegistry, inner: GuardrailBase | None = None) -> ExfilIntegrationBundleV22:
    return ExfilIntegrationFactoryV22.build(hook_registry=hook_registry, inner=inner)
