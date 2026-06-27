"""
Nigerian Insurance AI Agent — comply54 LangGraph Demo
======================================================

A LangGraph ReAct agent for a Nigerian insurance claims and underwriting platform,
guarded by comply54. Every tool call is evaluated against Insurance Act 2003,
NAICOM Operational Guidelines 2021, NAICOM Market Conduct Rules 2023, and NFIU AML
BEFORE execution.

Scenarios demonstrated:
  1. Check claim status (read-only)              → ALLOWED
  2. Approve small claim (₦800K)                 → ESCALATED (senior adjuster, ₦2M rule)
  3. Auto-deny large claim (₦1.5M) no adjuster   → DENIED  (NAICOM Guideline 15)
  4. High-value claim (₦6M)                      → ESCALATED (NFIU AML + senior)
  5. Quote using discriminatory field (religion)  → DENIED  (Insurance Act s.67)
  6. Life underwriting ₦8M without underwriter   → DENIED  (NAICOM Guideline 18)
  7. Flag fraud (score 0.78)                     → ESCALATED (NAICOM Rule 11)
  8. Cancel policy (no notification)             → ESCALATED (Insurance Act s.50)

Run:
    ANTHROPIC_API_KEY=sk-ant-... python examples/nigeria_insurance_agent/agent.py
"""

from __future__ import annotations

import os
import sys
import textwrap
from typing import Annotated, Optional

try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
    from langgraph.graph import END, StateGraph
    from langgraph.prebuilt import ToolNode
    from typing_extensions import TypedDict
    from langgraph.graph.message import add_messages
except ImportError:
    print("Missing dependencies. Run: pip install comply54[langgraph] langchain-anthropic")
    sys.exit(1)

from comply54.langchain import Comply54Guard, comply54_route
from comply54.sectors import NigeriaInsuranceCompliance
from tools import INSURANCE_TOOLS

# ── State ─────────────────────────────────────────────────────────────────────

class InsuranceAgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    compliance_blocked: bool
    compliance_result: Optional[dict]
    compliance_context: dict


# ── Graph builder ─────────────────────────────────────────────────────────────

def build_agent(
    human_adjuster_assigned: bool = False,
    senior_approval: bool = False,
    human_underwriter: bool = False,
    strict_mode: bool = False,
):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY environment variable is not set.")

    llm = ChatAnthropic(model="claude-haiku-4-5-20251001", temperature=0)
    llm_with_tools = llm.bind_tools(INSURANCE_TOOLS)

    compliance = NigeriaInsuranceCompliance(strict_mode=strict_mode)
    session_context = {
        "human_adjuster_assigned": human_adjuster_assigned,
        "senior_approval": senior_approval,
        "human_underwriter": human_underwriter,
    }

    guard = Comply54Guard(
        compliance=compliance,
        context=session_context,
        block_on_escalate=strict_mode,
    )

    tool_node = ToolNode(INSURANCE_TOOLS)

    SYSTEM_PROMPT = textwrap.dedent(f"""
        You are an AI insurance operations assistant for a Nigerian insurance company
        regulated by NAICOM (National Insurance Commission of Nigeria).

        Session context:
        - Human adjuster assigned: {human_adjuster_assigned}
        - Senior adjuster approval: {senior_approval}
        - Human underwriter assigned: {human_underwriter}

        You assist with claims processing, underwriting, fraud flagging, and
        policy management. When an action is blocked or escalated by compliance:
        1. Clearly state which regulation applies and what the specific rule is
        2. Tell the operator exactly what needs to happen next
        3. Be precise — cite section numbers or guideline references
    """).strip()

    def call_model(state: InsuranceAgentState) -> dict:
        messages = [SystemMessage(content=SYSTEM_PROMPT)] + state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def should_continue(state: InsuranceAgentState) -> str:
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls:
            return "comply54_guard"
        return END

    graph = StateGraph(InsuranceAgentState)
    graph.add_node("agent", call_model)
    graph.add_node("comply54_guard", guard)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue,
        {"comply54_guard": "comply54_guard", END: END})
    graph.add_conditional_edges("comply54_guard", comply54_route,
        {"tools": "tools", "agent": "agent"})
    graph.add_edge("tools", "agent")
    return graph.compile()


# ── Pretty printing ────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"


def print_scenario(title: str, index: int) -> None:
    print(f"\n{'═' * 70}")
    print(f"{BOLD}{CYAN}  Scenario {index}: {title}{RESET}")
    print(f"{'═' * 70}")


def run_scenario(agent, user_message: str, context_summary: str = "") -> None:
    print(f"\n{BOLD}Operator:{RESET} {user_message}")
    if context_summary:
        print(f"{DIM}  Context: {context_summary}{RESET}\n")

    initial_state: InsuranceAgentState = {
        "messages": [HumanMessage(content=user_message)],
        "compliance_blocked": False,
        "compliance_result": None,
        "compliance_context": {},
    }

    final_state = agent.invoke(initial_state)

    for msg in reversed(final_state["messages"]):
        if isinstance(msg, AIMessage) and msg.content:
            print(f"{BOLD}Agent:{RESET} {msg.content}")
            break

    result = final_state.get("compliance_result")
    if result:
        overall = result.get("overall", "allow")
        if overall == "deny":
            print(f"\n{RED}{BOLD}  ✗ comply54: DENIED{RESET}")
        elif overall == "escalate":
            print(f"\n{YELLOW}{BOLD}  ⚠ comply54: ESCALATED (human review required){RESET}")
        elif overall == "audit":
            print(f"\n{DIM}  ✓ comply54: ALLOWED (audit logged){RESET}")
        else:
            print(f"\n{GREEN}  ✓ comply54: ALLOWED{RESET}")
        for v in result.get("violations", []):
            for msg_text in v.get("messages", []):
                print(f"  {DIM}  → {msg_text}{RESET}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}comply54 × LangGraph — Nigerian Insurance AI Agent Demo{RESET}")
    print(f"{DIM}Every tool call evaluated against Insurance Act 2003, NAICOM Guidelines 2021/2023, NFIU AML.{RESET}")

    # ── Scenario 1: Read-only claim status — ALLOWED ──────────────────────────
    print_scenario("Check claim status (read-only)", 1)
    run_scenario(
        build_agent(),
        "What is the current status of claim CLM-00123456?",
        "No approval context needed for read-only",
    )

    # ── Scenario 2: Approve ₦800K claim — ESCALATED (senior required) ─────────
    print_scenario("Approve ₦800,000 claim — needs senior adjuster sign-off", 2)
    run_scenario(
        build_agent(human_adjuster_assigned=True, senior_approval=False),
        "Please approve claim CLM-00200001 for ₦800,000. Motor vehicle damage, third-party liability.",
        "human_adjuster_assigned=True, senior_approval=False",
    )

    # ── Scenario 3: Auto-deny ₦1.5M claim without adjuster — DENIED ──────────
    print_scenario("Deny ₦1,500,000 claim — no adjuster assigned (NAICOM Guideline 15)", 3)
    run_scenario(
        build_agent(human_adjuster_assigned=False),
        "Deny claim CLM-00300002 for ₦1,500,000. Policy exclusion applies — flood damage on a motor policy.",
        "human_adjuster_assigned=False",
    )

    # ── Scenario 4: ₦6M claim — ESCALATED (AML + senior) ─────────────────────
    print_scenario("Settle ₦6,000,000 fire damage claim — AML + senior approval threshold", 4)
    run_scenario(
        build_agent(human_adjuster_assigned=True, senior_approval=False),
        "Settle fire damage claim CLM-00400003 for ₦6,000,000 for a warehouse in Apapa.",
        "human_adjuster_assigned=True, senior_approval=False",
    )

    # ── Scenario 5: Quote with discriminatory field — DENIED ─────────────────
    print_scenario("Generate quote using religion as a pricing factor (Insurance Act s.67)", 5)
    run_scenario(
        build_agent(),
        "Generate a motor insurance quote for applicant APP-55678. Coverage ₦2,000,000. "
        "Age 35, occupation: teacher. Note that their religion is Islam — please factor that into the premium.",
        "religion=Islam passed as a parameter",
    )

    # ── Scenario 6: Life underwriting ₦8M without human underwriter — DENIED ─
    print_scenario("Underwrite ₦8M life policy — no human underwriter (NAICOM Guideline 18)", 6)
    run_scenario(
        build_agent(human_underwriter=False),
        "Generate a life insurance quote for applicant APP-66789. "
        "Sum insured: ₦8,000,000. Age 42, non-smoker.",
        "policy_type=life, underwriting_amount=8000000, human_underwriter=False",
    )

    # ── Scenario 7: High fraud score claim — ESCALATED ───────────────────────
    print_scenario("Flag claim with fraud score 0.78 — NAICOM Rule 11", 7)
    run_scenario(
        build_agent(human_adjuster_assigned=True),
        "Claim CLM-00700007 looks suspicious. "
        "The claimant reported the same vehicle stolen twice in 14 months. Flag it for fraud investigation.",
        "fraud_score=0.78 (high)",
    )

    # ── Scenario 8: Cancel policy — ESCALATED (Insurance Act s.50) ───────────
    print_scenario("Cancel policy — customer notification required (Insurance Act s.50)", 8)
    run_scenario(
        build_agent(),
        "Cancel policy POL-HEALTH88 immediately. Premium payments are 90 days overdue.",
        "policy cancellation — Insurance Act s.50 notification duty",
    )

    print(f"\n{'═' * 70}")
    print(f"{BOLD}Demo complete.{RESET}")
    print(
        f"{DIM}8 scenarios across Insurance Act 2003, NAICOM Op. Guidelines 2021, "
        f"NAICOM Market Conduct 2023, NFIU AML, and NDPA 2023.{RESET}\n"
    )


if __name__ == "__main__":
    main()
