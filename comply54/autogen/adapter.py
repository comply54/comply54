"""
comply54.autogen.adapter
~~~~~~~~~~~~~~~~~~~~~~~~
Microsoft AutoGen integration for comply54.

Targets autogen-agentchat / autogen-core ≥ 0.4 (the ``autogen-agentchat`` package).

Provides:
  comply54_tool()     — Wrap a single callable with pre-execution compliance enforcement.
                        Returns a FunctionTool ready for AssistantAgent(tools=[...]).
  comply54_tools()    — Bulk-wrap a list of callables / FunctionTools.
  compliance_tool()   — Create a standalone self-check FunctionTool (passive; the LLM
                        must choose to call it).

Automatic enforcement pattern (recommended):

    from comply54.autogen import comply54_tools
    from comply54.sectors import NigeriaFintechCompliance
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    compliance = NigeriaFintechCompliance()
    client = OpenAIChatCompletionClient(model="gpt-4o")

    agent = AssistantAgent(
        name="finance_agent",
        model_client=client,
        tools=comply54_tools([transfer_funds, check_balance], compliance),
    )

Self-check tool pattern (agent decides when to call it):

    from comply54.autogen import compliance_tool

    agent = AssistantAgent(
        name="finance_agent",
        model_client=client,
        tools=[transfer_funds, compliance_tool(NigeriaFintechCompliance())],
    )

Migrating from autogen-agentchat < 0.4 / pyautogen:

    # Before (pyautogen ≤ 0.2):
    from comply54.autogen import Comply54UserProxy, register_compliance_guard
    proxy = Comply54UserProxy(compliance, name="proxy", ...)

    # After (autogen-agentchat ≥ 0.4):
    from comply54.autogen import comply54_tools
    agent = AssistantAgent(
        name="agent", model_client=client,
        tools=comply54_tools([your_tool], compliance),
    )
"""

from __future__ import annotations

import functools
import inspect
import json
import warnings
from typing import Any, Callable

from ..core.models import ComplianceResult
from ..sectors._base import SectorCompliance


# ─── Lazy import helper ───────────────────────────────────────────────────────

def _require_function_tool() -> type:
    try:
        from autogen_core.tools import FunctionTool  # type: ignore[import-untyped]

        return FunctionTool
    except ImportError as exc:
        raise ImportError(
            "autogen-agentchat is required. Install with: pip install comply54[autogen]"
        ) from exc


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _violation_payload(result: ComplianceResult, compliance: SectorCompliance) -> str:
    """Serialise a blocked ComplianceResult to a JSON string for the LLM."""
    violation = result.primary_violation
    return json.dumps({
        "blocked": True,
        "decision": result.overall,
        "reason": (
            violation.messages[0]
            if violation and violation.messages
            else "Compliance check failed"
        ),
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


# ─── Primary API ──────────────────────────────────────────────────────────────

def comply54_tool(
    fn: Callable[..., Any],
    compliance: SectorCompliance,
    description: str = "",
    context: dict | None = None,
    block_on_escalate: bool = False,
    name: str | None = None,
) -> Any:
    """
    Wrap a callable with comply54 pre-execution compliance enforcement.

    Before the function executes, the compliance pack evaluates the action name
    and keyword arguments.  A ``"deny"`` decision (or ``"escalate"`` when
    ``block_on_escalate=True``) returns a structured JSON error to the model
    without running the function.  Any other decision allows execution to
    proceed normally.

    The original function's type annotations are preserved so that AutoGen can
    generate the correct tool schema.

    Args:
        fn:                The callable to wrap (sync or async).
        compliance:        A SectorCompliance instance.
        description:       Tool description forwarded to FunctionTool. Defaults to
                           ``fn.__doc__``.
        context:           Default session context applied to every evaluation
                           (e.g. ``{"kyc_tier": 3}``).
        block_on_escalate: Treat ``"escalate"`` decisions as blocks. Default
                           ``False`` — escalations are flagged but the function
                           still executes so the agent can surface the reason.
        name:              Override the tool name. Defaults to ``fn.__name__``.

    Returns:
        A ``FunctionTool`` ready for ``AssistantAgent(tools=[...])``.

    Usage::

        safe_transfer = comply54_tool(transfer_funds, NigeriaFintechCompliance())
        agent = AssistantAgent(
            name="finance_agent", model_client=client,
            tools=[safe_transfer],
        )
    """
    FunctionTool = _require_function_tool()
    ctx = context or {}
    tool_name = name or fn.__name__

    @functools.wraps(fn)
    async def _guarded(*args: Any, **kwargs: Any) -> Any:
        result = compliance.check(action=tool_name, params=kwargs, context=ctx)
        is_blocked = result.overall == "deny" or (
            block_on_escalate and result.overall == "escalate"
        )
        if is_blocked:
            return _violation_payload(result, compliance)
        if inspect.iscoroutinefunction(fn):
            return await fn(*args, **kwargs)
        return fn(*args, **kwargs)

    # Preserve the original parameter signature so FunctionTool generates the
    # correct JSON schema from type annotations.
    _guarded.__signature__ = inspect.signature(fn)  # type: ignore[attr-defined]

    return FunctionTool(
        _guarded,
        description=description or fn.__doc__ or tool_name,
        name=tool_name,
    )


def comply54_tools(
    tools: list[Callable[..., Any] | Any],
    compliance: SectorCompliance,
    context: dict | None = None,
    block_on_escalate: bool = False,
) -> list[Any]:
    """
    Wrap a list of callables or FunctionTools with comply54 compliance enforcement.

    All tools in the list are wrapped with the same compliance pack and context.
    Existing ``FunctionTool`` instances are re-wrapped preserving their name and
    description.

    Args:
        tools:             List of callables or ``FunctionTool`` instances.
        compliance:        A SectorCompliance instance.
        context:           Default session context applied to every evaluation.
        block_on_escalate: Treat ``"escalate"`` decisions as blocks. Default
                           ``False``.

    Returns:
        A list of ``FunctionTool`` instances ready for
        ``AssistantAgent(tools=[...])``.

    Usage::

        agent = AssistantAgent(
            name="finance_agent",
            model_client=client,
            tools=comply54_tools([transfer_funds, check_balance], compliance),
        )
    """
    FunctionTool = _require_function_tool()
    guarded: list[Any] = []

    for tool in tools:
        if isinstance(tool, FunctionTool):
            # Re-wrap the underlying callable, preserving name and description.
            guarded.append(
                comply54_tool(
                    tool._func,  # internal attr; stable across autogen-core 0.4.x
                    compliance,
                    description=tool.description,
                    context=context,
                    block_on_escalate=block_on_escalate,
                    name=tool.name,
                )
            )
        else:
            guarded.append(
                comply54_tool(
                    tool,
                    compliance,
                    context=context,
                    block_on_escalate=block_on_escalate,
                )
            )

    return guarded


def compliance_tool(compliance: SectorCompliance) -> Any:
    """
    Create a standalone comply54 self-check ``FunctionTool``.

    Unlike ``comply54_tool``, this tool is *passive* — the agent must explicitly
    call it to run a compliance check.  Use this pattern when you want the LLM
    to reason about compliance before acting rather than having the runtime block
    the action automatically.

    Args:
        compliance: A SectorCompliance instance.

    Returns:
        A ``FunctionTool`` to include in ``AssistantAgent(tools=[...])``.

    Usage::

        agent = AssistantAgent(
            name="finance_agent",
            model_client=client,
            tools=[transfer_funds, compliance_tool(NigeriaFintechCompliance())],
        )
    """
    FunctionTool = _require_function_tool()

    fn_name = f"comply54_{compliance.__class__.__name__.lower()}"
    doc = (
        f"comply54 compliance check: {compliance.name}. "
        f"Jurisdictions: {', '.join(compliance.jurisdictions)}. "
        "Returns JSON with overall decision (allow/deny/escalate/audit), "
        "triggered rule, and exact regulatory citations."
    )

    def _check(
        action: str,
        params: str = "{}",
        output: str = "",
        context: str = "{}",
    ) -> str:
        result = compliance.check(
            action=action,
            params=json.loads(params) if params else {},
            output=output,
            context=json.loads(context) if context else {},
        )
        return json.dumps(_result_to_dict(result))

    _check.__name__ = fn_name
    _check.__doc__ = doc

    return FunctionTool(_check, description=doc, name=fn_name)


# ─── Deprecated v0.2 / pyautogen API ──────────────────────────────────────────

def Comply54UserProxy(*_args: Any, **_kwargs: Any) -> None:  # noqa: N802
    """Removed. Use comply54_tools() with AssistantAgent instead."""
    raise ImportError(
        "Comply54UserProxy requires pyautogen ≤ 0.2 which is incompatible with "
        "autogen-agentchat ≥ 0.4.\n\n"
        "Migrate to comply54_tools():\n\n"
        "    from comply54.autogen import comply54_tools\n"
        "    from autogen_agentchat.agents import AssistantAgent\n\n"
        "    agent = AssistantAgent(\n"
        "        name='agent', model_client=client,\n"
        "        tools=comply54_tools([your_tool], compliance),\n"
        "    )\n\n"
        "See: https://comply54.io/docs/integrations/autogen"
    )


def register_compliance_guard(*_args: Any, **_kwargs: Any) -> None:
    """Removed. Use comply54_tools() with AssistantAgent instead."""
    raise ImportError(
        "register_compliance_guard() requires pyautogen ≤ 0.2 which is incompatible "
        "with autogen-agentchat ≥ 0.4.\n\n"
        "Use comply54_tools() when constructing the agent. "
        "See: https://comply54.io/docs/integrations/autogen"
    )


def register_compliance(agent: Any, compliance: SectorCompliance) -> Any:
    """
    Deprecated. Use compliance_tool() and pass it to AssistantAgent(tools=[...]).

    In autogen-agentchat ≥ 0.4 tools cannot be added to an agent after
    construction.  This function emits a DeprecationWarning and returns the
    FunctionTool so you can add it yourself.
    """
    warnings.warn(
        "register_compliance() is deprecated for autogen-agentchat ≥ 0.4. "
        "Use compliance_tool(compliance) and include it in "
        "AssistantAgent(tools=[..., compliance_tool(compliance)]).",
        DeprecationWarning,
        stacklevel=2,
    )
    return compliance_tool(compliance)
