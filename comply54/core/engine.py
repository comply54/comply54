"""
comply54.core.engine
~~~~~~~~~~~~~~~~~~~~
Rego policy evaluation engine built on regopy.

Evaluates multiple comply54 packs in two in-process Rego queries —
no OPA binary, no subprocess, no external dependencies beyond `regopy`.

Strategy: two-pass evaluation
  Pass 1 — query all pack decisions (one variable per pack, minimal query size)
  Pass 2 — query messages only for non-allow packs (skipped entirely on full pass)
"""

from __future__ import annotations

import json
import threading

from regopy import Interpreter

from .citations import RULE_CITATIONS
from .models import Action, ComplianceResult, EvaluationInput, PolicyDecision, RegulatorySource
from .packs import PackSpec


_SEVERITY: dict[Action, int] = {"allow": 0, "audit": 1, "escalate": 2, "deny": 3}

# Interpreters keyed by frozenset of pack IDs — modules loaded once, reused
_interp_cache: dict[frozenset, Interpreter] = {}
_cache_lock = threading.Lock()


def _build_interpreter(packs: list[PackSpec]) -> Interpreter:
    interp = Interpreter()
    for pack in packs:
        interp.add_module(pack.module_name, pack.rego_source)
    return interp


def _get_interpreter(packs: list[PackSpec]) -> Interpreter:
    key = frozenset(p.id for p in packs)
    with _cache_lock:
        if key not in _interp_cache:
            _interp_cache[key] = _build_interpreter(packs)
        return _interp_cache[key]


def _query(interp: Interpreter, input_json: str, query_body: str) -> dict:
    """Run a query with embedded input and return the bindings dict."""
    q = f"input := {input_json}; {query_body}"
    raw = str(interp.query(q))
    if not raw or raw.strip() == "undefined":
        return {}
    return json.loads(raw).get("bindings", {})


class Comply54Engine:
    """
    Core evaluation engine for comply54.

    Evaluates a list of policy packs against an agent action using
    in-process Rego evaluation (regopy). No OPA binary required.

    Usage:
        engine = Comply54Engine(packs=[CBN, NDPA, BVN_NIN, PII_LEAKAGE])
        result = engine.evaluate(EvaluationInput(
            action="transfer_funds",
            params={"amount": 15_000_000, "currency": "NGN"},
        ))
        if result.blocked:
            raise ValueError(result.primary_violation.messages[0])

    Signed receipts (optional)::

        private_pem, public_pem = ReceiptSigner.generate_keypair()
        engine = Comply54Engine(packs=[CBN, NDPA], signing_key=private_pem)
        result = engine.check(action="transfer_funds", params={"amount": 500_000})
        print(result.receipt_token)  # compact JWT

    Note: when using sector packs (e.g. ``NigeriaFintechCompliance``), pass
    ``signing_key`` to the sector pack instead — it signs after applying
    ``strict_mode``, so the receipt accurately reflects the final decision.
    """

    def __init__(
        self,
        packs: list[PackSpec],
        cache: bool = True,
        signing_key: "bytes | str | None" = None,
    ) -> None:
        self._packs = packs
        self._cache = cache
        self._signer: "ReceiptSigner | None" = None
        if signing_key is not None:
            from ..receipts._signer import ReceiptSigner
            self._signer = ReceiptSigner(signing_key)

    def evaluate(self, input: EvaluationInput | dict) -> ComplianceResult:
        """
        Evaluate all packs against the given input.

        Args:
            input: An EvaluationInput (or plain dict with the same keys).

        Returns:
            ComplianceResult with per-pack decisions and aggregate outcome.
        """
        if isinstance(input, dict):
            input = EvaluationInput(**input)

        input_json = json.dumps(input.to_rego_input())

        interp = _get_interpreter(self._packs) if self._cache else _build_interpreter(self._packs)

        # ── Pass 1: get decisions for all packs ───────────────────────────────
        q1 = "; ".join(
            f"p{i}_d := {p.query_prefix}.decision"
            for i, p in enumerate(self._packs)
        )
        bindings1 = _query(interp, input_json, q1)

        if not bindings1:
            # Fallback: evaluate each pack independently (graceful degradation)
            result = self._evaluate_individually(input_json)
            if self._signer is not None:
                token = self._signer.sign(result, input.action, input.params, input.output, input.context)
                result = result.model_copy(update={"receipt_token": token})
            return result

        decisions_step1: list[tuple[int, PackSpec, Action]] = [
            (i, p, bindings1.get(f"p{i}_d", "allow"))
            for i, p in enumerate(self._packs)
        ]

        # ── Pass 2: get messages + citation keys for non-allow packs ─────────
        non_allow = [(i, p, a) for i, p, a in decisions_step1 if a != "allow"]
        messages_by_index: dict[int, list[str]] = {}
        rule_keys_by_index: dict[int, list[str]] = {}

        if non_allow:
            q2_parts: list[str] = []
            for i, p, action in non_allow:
                q2_parts.append(f"p{i}_msgs := {p.query_prefix}.{action}")
                q2_parts.append(f"p{i}_cites := {p.query_prefix}.{action}_citations")
            bindings2 = _query(interp, input_json, "; ".join(q2_parts))
            for i, p, action in non_allow:
                raw_msgs = bindings2.get(f"p{i}_msgs", []) or []
                raw_cites = bindings2.get(f"p{i}_cites", []) or []
                messages_by_index[i] = list(raw_msgs)
                rule_keys_by_index[i] = sorted(raw_cites)  # deterministic order

        # ── Build PolicyDecision objects ──────────────────────────────────────
        decisions: list[PolicyDecision] = []
        for i, p, action in decisions_step1:
            rule_keys = rule_keys_by_index.get(i, [])
            rule_triggered = rule_keys[0] if rule_keys else None
            specific: list[RegulatorySource] = []
            for key in rule_keys:
                specific.extend(RULE_CITATIONS.get(f"{p.id}.{key}", []))
            decisions.append(PolicyDecision(
                pack=p.id,
                regulation=p.regulation,
                jurisdiction=p.jurisdiction,
                action=action,
                messages=messages_by_index.get(i, []),
                citations=specific if specific else list(p.sources),
                rule_triggered=rule_triggered,
            ))

        result = ComplianceResult.from_decisions(decisions)
        if self._signer is not None:
            token = self._signer.sign(result, input.action, input.params, input.output, input.context)
            result = result.model_copy(update={"receipt_token": token})
        return result

    def _evaluate_individually(self, input_json: str) -> ComplianceResult:
        """Fallback: evaluate each pack with its own interpreter."""
        decisions: list[PolicyDecision] = []
        for pack in self._packs:
            interp = Interpreter()
            interp.add_module(pack.module_name, pack.rego_source)

            q_d = f"d := {pack.query_prefix}.decision"
            b = _query(interp, input_json, q_d)
            action: Action = b.get("d", "allow")

            messages: list[str] = []
            rule_keys: list[str] = []
            if action != "allow":
                q_m = f"msgs := {pack.query_prefix}.{action}; cites := {pack.query_prefix}.{action}_citations"
                bm = _query(interp, input_json, q_m)
                messages = list(bm.get("msgs", []) or [])
                rule_keys = sorted(bm.get("cites", []) or [])

            rule_triggered = rule_keys[0] if rule_keys else None
            specific: list[RegulatorySource] = []
            for key in rule_keys:
                specific.extend(RULE_CITATIONS.get(f"{pack.id}.{key}", []))

            decisions.append(PolicyDecision(
                pack=pack.id,
                regulation=pack.regulation,
                jurisdiction=pack.jurisdiction,
                action=action,
                messages=messages,
                citations=specific if specific else list(pack.sources),
                rule_triggered=rule_triggered,
            ))
        return ComplianceResult.from_decisions(decisions)

    def check(
        self,
        action: str,
        params: dict | None = None,
        output: str = "",
        context: dict | None = None,
    ) -> ComplianceResult:
        """Convenience wrapper — pass action fields directly."""
        return self.evaluate(EvaluationInput(
            action=action,
            params=params or {},
            output=output,
            context=context or {},
        ))

    @property
    def packs(self) -> list[PackSpec]:
        return list(self._packs)

    def __repr__(self) -> str:
        ids = ", ".join(p.id for p in self._packs)
        return f"Comply54Engine(packs=[{ids}])"
