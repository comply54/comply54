"""
comply54.autogen.adapter
~~~~~~~~~~~~~~~~~~~~~~~~
Microsoft AutoGen integration for comply54.

Provides:
  - Comply54UserProxy       — UserProxyAgent subclass that intercepts every
                              function/tool call and enforces comply54 before execution
  - register_compliance_guard() — Patch any existing UserProxyAgent in-place
  - register_compliance()   — Register a self-check compliance tool on an agent
                              (passive; the LLM must choose to call it)

Automatic enforcement pattern (recommended):

    from comply54.autogen import Comply54UserProxy
    from comply54.sectors import NigeriaFintechCompliance

    proxy = Comply54UserProxy(
        NigeriaFintechCompliance(),
        name="user_proxy",
        human_input_mode="NEVER",
        context={"kyc_tier": 3},
    )
    proxy.initiate_chat(assistant, message="Transfer ₦15,000,000 to 0123456789")

Patch an existing proxy:

    from comply54.autogen import register_compliance_guard

    register_compliance_guard(existing_proxy, NigeriaFintechCompliance())

Self-check tool pattern (agent decides when to call it):

    from comply54.autogen import register_compliance

    register_compliance(assistant, NigeriaFintechCompliance())
    register_compliance(proxy,     NigeriaFintechCompliance())
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from ..core.models import ComplianceResult
from ..sectors._base import SectorCompliance


# ─── Comply54UserProxy ────────────────────────────────────────────────────────

class Comply54UserProxy:
    """
    A comply54-aware AutoGen UserProxyAgent that enforces compliance before
    every function / tool call.

    Drop-in replacement for ``autogen.UserProxyAgent``.  Before executing any
    registered function, it evaluates the function name and decoded arguments
    against the configured SectorCompliance pack.  Blocked calls return a
    structured error dict to the conversation thread without executing the
    function — the assistant sees the error and can respond to the user.

    Args:
        compliance:        A SectorCompliance instance.
        context:           Default session context (e.g. {"kyc_tier": 3}).
                           Applied to every evaluation.
        block_on_escalate: Also block "escalate" decisions. Default False —
                           escalate is flagged but allowed so the assistant
                           can surface the escalation reason.
        **kwargs:          All remaining kwargs forwarded to UserProxyAgent.

    Usage:
        proxy = Comply54UserProxy(
            NigeriaFintechCompliance(),
            name="user_proxy",
            human_input_mode="NEVER",
            code_execution_config=False,
            context={"kyc_tier": 3},
        )
        proxy.initiate_chat(assistant, message="Transfer ₦20,000,000")
    """

    def __new__(
        cls,
        compliance: SectorCompliance,
        context: dict | None = None,
        block_on_escalate: bool = False,
        **kwargs: Any,
    ) -> Any:
        try:
            from autogen import UserProxyAgent
        except ImportError as exc:
            raise ImportError(
                "pyautogen is required. Install with: pip install comply54[autogen]"
            ) from exc

        ctx = context or {}

        class _GuardedProxy(UserProxyAgent):
            """UserProxyAgent with comply54 pre-execution enforcement."""

            def execute_function(
                self,
                func_call: dict[str, Any],
                verbose: bool = False,
            ) -> tuple[bool, dict[str, Any]]:
                func_name = func_call.get("name", "")
                args_raw = func_call.get("arguments", "{}")

                # AutoGen may deliver arguments as a JSON string or a dict.
                if isinstance(args_raw, str):
                    try:
                        args = json.loads(args_raw) if args_raw.strip() else {}
                    except json.JSONDecodeError:
                        args = {}
                else:
                    args = args_raw or {}

                result = compliance.check(
                    action=func_name,
                    params=args,
                    context=ctx,
                )
                is_blocked = result.overall == "deny" or (
                    block_on_escalate and result.overall == "escalate"
                )

                if is_blocked:
                    violation = result.primary_violation
                    reason = (
                        violation.messages[0]
                        if violation and violation.messages
                        else "Compliance check failed"
                    )
                    blocked_content = json.dumps({
                        "blocked": True,
                        "decision": result.overall,
                        "reason": reason,
                        "regulation": violation.regulation if violation else compliance.name,
                        "rule_triggered": violation.rule_triggered if violation else None,
                        "citations": [
                            {
                                "document": c.document,
                                "section": c.section,
                                "authority": c.authority,
                                "year": c.year,
                            }
                            for c in (violation.citations if violation else [])
                        ],
                        "audit_id": result.audit_id,
                        "jurisdictions": compliance.jurisdictions,
                    })
                    return False, {
                        "name": func_name,
                        "role": "tool",
                        "content": blocked_content,
                    }

                return super().execute_function(func_call, verbose=verbose)

        _GuardedProxy.__name__ = "Comply54UserProxy"
        _GuardedProxy.__qualname__ = "Comply54UserProxy"
        return _GuardedProxy(**kwargs)


# ─── Patch helper ─────────────────────────────────────────────────────────────

def register_compliance_guard(
    proxy: Any,
    compliance: SectorCompliance,
    context: dict | None = None,
    block_on_escalate: bool = False,
) -> None:
    """
    Patch an existing AutoGen UserProxyAgent to enforce comply54 before
    every function call.  Mutates the proxy instance in-place.

    Prefer Comply54UserProxy for new agents.  Use this function when you
    cannot control proxy construction (e.g. third-party scaffolding).

    Args:
        proxy:             An existing autogen ConversableAgent / UserProxyAgent.
        compliance:        A SectorCompliance instance.
        context:           Default session context.
        block_on_escalate: Also block "escalate" decisions. Default False.

    Usage:
        register_compliance_guard(existing_proxy, NigeriaFintechCompliance())
    """
    ctx = context or {}
    original_execute = proxy.execute_function  # already-bound method

    def _guarded_execute(
        func_call: dict[str, Any],
        verbose: bool = False,
    ) -> tuple[bool, dict[str, Any]]:
        func_name = func_call.get("name", "")
        args_raw = func_call.get("arguments", "{}")

        if isinstance(args_raw, str):
            try:
                args = json.loads(args_raw) if args_raw.strip() else {}
            except json.JSONDecodeError:
                args = {}
        else:
            args = args_raw or {}

        result = compliance.check(
            action=func_name,
            params=args,
            context=ctx,
        )
        is_blocked = result.overall == "deny" or (
            block_on_escalate and result.overall == "escalate"
        )

        if is_blocked:
            violation = result.primary_violation
            reason = (
                violation.messages[0]
                if violation and violation.messages
                else "Compliance check failed"
            )
            blocked_content = json.dumps({
                "blocked": True,
                "decision": result.overall,
                "reason": reason,
                "regulation": violation.regulation if violation else compliance.name,
                "rule_triggered": violation.rule_triggered if violation else None,
                "citations": [
                    {
                        "document": c.document,
                        "section": c.section,
                        "authority": c.authority,
                        "year": c.year,
                    }
                    for c in (violation.citations if violation else [])
                ],
                "audit_id": result.audit_id,
                "jurisdictions": compliance.jurisdictions,
            })
            return False, {
                "name": func_name,
                "role": "tool",
                "content": blocked_content,
            }

        return original_execute(func_call, verbose)

    # Replace instance-level attribute so super() chains inside the class
    # still work for other methods while only execute_function is patched.
    import types
    proxy.execute_function = types.MethodType(
        lambda self, fc, v=False: _guarded_execute(fc, v),
        proxy,
    )


# ─── Self-check tool registration ─────────────────────────────────────────────

def register_compliance(agent: Any, compliance: SectorCompliance) -> None:
    """
    Register a comply54 SectorCompliance pack as a callable function tool on
    an AutoGen ConversableAgent or AssistantAgent.

    The agent can call this function to self-check an action.  For automatic
    pre-execution enforcement use Comply54UserProxy or register_compliance_guard.

    Args:
        agent:      An autogen ConversableAgent or AssistantAgent.
        compliance: A SectorCompliance instance.

    Usage:
        register_compliance(assistant, NigeriaFintechCompliance())
        register_compliance(proxy,     NigeriaFintechCompliance())
    """

    def check_compliance(
        action: Annotated[str, "The agent action or tool name to evaluate."],
        params: Annotated[str, "JSON-encoded parameters dict."] = "{}",
        output: Annotated[str, "The agent's proposed output text."] = "",
        context: Annotated[str, "JSON-encoded session context dict."] = "{}",
    ) -> str:
        result = compliance.check(
            action=action,
            params=json.loads(params) if params else {},
            output=output,
            context=json.loads(context) if context else {},
        )
        return json.dumps(_result_to_dict(result))

    fn_name = f"comply54_{compliance.__class__.__name__.lower()}"
    check_compliance.__name__ = fn_name
    check_compliance.__doc__ = (
        f"comply54 compliance check: {compliance.name}. "
        f"Jurisdictions: {', '.join(compliance.jurisdictions)}. "
        "Returns JSON with overall decision (allow/deny/escalate/audit), "
        "triggered rule, and exact regulatory citations."
    )

    try:
        agent.register_for_llm(
            name=fn_name,
            description=check_compliance.__doc__,
        )(check_compliance)
    except AttributeError as exc:
        raise ImportError(
            "pyautogen is required. Install with: pip install comply54[autogen]"
        ) from exc


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _result_to_dict(result: ComplianceResult) -> dict:
    return {
        "overall": result.overall,
        "blocked": result.blocked,
        "audit_id": result.audit_id,
        "violations": [
            {
                "pack": d.pack,
                "regulation": d.regulation,
                "jurisdiction": d.jurisdiction,
                "action": d.action,
                "messages": d.messages,
                "rule_triggered": d.rule_triggered,
                "citations": [
                    {
                        "document": c.document,
                        "section": c.section,
                        "authority": c.authority,
                        "year": c.year,
                    }
                    for c in d.citations
                ],
            }
            for d in result.violations
        ],
    }
