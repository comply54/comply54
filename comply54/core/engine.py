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
import re
import threading

from regopy import Interpreter

from .citations import RULE_CITATIONS
from .models import Action, ComplianceResult, EvaluationInput, PolicyDecision, RegulatorySource
from .packs import PackSpec

_SEVERITY: dict[Action, int] = {"allow": 0, "audit": 1, "escalate": 2, "deny": 3}

# Interpreters keyed by frozenset of pack IDs — modules loaded once, reused
_interp_cache: dict[frozenset, Interpreter] = {}
_cache_lock = threading.Lock()


def _python_to_rego(value: object) -> str:
    """Serialize a Python value to its Rego literal equivalent."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        # Same normalisation as evaluation input, so a deployer pattern
        # containing a line break still matches normalised input text.
        escaped = _normalise_text(value).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, (set, frozenset)):
        if not value:
            return "set()"
        items = ", ".join(sorted(_python_to_rego(v) for v in value))
        return "{" + items + "}"
    if isinstance(value, list):
        items = ", ".join(_python_to_rego(v) for v in value)
        return "[" + items + "]"
    if isinstance(value, dict):
        pairs = ", ".join(
            f"{_python_to_rego(k)}: {_python_to_rego(v)}"
            for k, v in value.items()
        )
        return "{" + pairs + "}"
    return f'"{value}"'


def _build_config_modules(config: dict) -> list[tuple[str, str]]:
    """Generate synthetic Rego modules that populate data.config.<pack>.* for deployer overrides."""
    modules: list[tuple[str, str]] = []
    for pack_name, pack_conf in config.items():
        pkg = f"config.{pack_name}"
        lines = [f"package {pkg}", "import rego.v1", ""]
        for key, value in pack_conf.items():
            lines.append(f"{key} := {_python_to_rego(value)}")
        modules.append((f"__config__{pack_name}", "\n".join(lines)))
    return modules


def _build_interpreter(packs: list[PackSpec], config: dict | None = None) -> Interpreter:
    interp = Interpreter()
    for pack in packs:
        interp.add_module(pack.module_name, pack.rego_source)
    if config:
        for module_name, rego_source in _build_config_modules(config):
            interp.add_module(module_name, rego_source)
    return interp


def _get_interpreter(packs: list[PackSpec]) -> Interpreter:
    key = frozenset(p.id for p in packs)
    with _cache_lock:
        if key not in _interp_cache:
            _interp_cache[key] = _build_interpreter(packs)
        return _interp_cache[key]


# regopy (rego-cpp) does not decode escape sequences in string literals, and its
# output parser crashes on raw control characters. Input text is therefore
# normalised before it is embedded in a query:
#   - \t \n \f \r (exactly the characters RE2's \s matches) become a space, so
#     every \s pattern behaves as it does under OPA. Consequence: `.` can span a
#     former line break under regopy, which can only add matches, never remove
#     them.
#   - every other C0 control character becomes DEL (U+007F): a single byte that,
#     like the control character, is not whitespace, word or digit to RE2.
#   - lone surrogates (not encodable as UTF-8) become U+FFFD.
_RE2_WHITESPACE = "\t\n\f\r"
_CONTROL_MAP = {
    code: (" " if chr(code) in _RE2_WHITESPACE else "\x7f")
    for code in range(0x20)
}
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")

# regopy's regex engine is byte-oriented: `.`, `[^x]`, `\S`, `\W` and `\D` each
# consume one byte, so a multi-byte UTF-8 character inside a wildcard span
# breaks the match (OPA/RE2 in UTF-8 mode consumes one character). Every
# non-ASCII character behaves exactly like DEL for all of those constructs in
# RE2 (not \s, \w or \d; matches `.`, \S, \W, \D and negated classes), so the
# agent output that regex rules scan has each non-ASCII character replaced by
# DEL, except characters that the loaded packs or config mention literally
# (e.g. ₦, Arabic letters), which must stay matchable.
_FOLD_PLACEHOLDER = "\x7f"


def _non_ascii_chars(sources: list[str]) -> frozenset[str]:
    """Non-ASCII characters appearing in Rego sources, with their case variants."""
    chars = {ch for src in sources for ch in src if ord(ch) > 127}
    variants = {v for ch in chars for v in (ch.lower(), ch.upper()) if len(v) == 1}
    return frozenset(chars | variants)


def _fold_non_ascii(text: str, keep: frozenset[str]) -> str:
    return "".join(
        ch if ord(ch) < 128 or ch in keep else _FOLD_PLACEHOLDER for ch in text
    )


def _normalise_text(text: str) -> str:
    return _LONE_SURROGATE.sub("�", text.translate(_CONTROL_MAP))


def _normalise_value(value: object) -> object:
    if isinstance(value, str):
        return _normalise_text(value)
    if isinstance(value, dict):
        return {
            (_normalise_text(k) if isinstance(k, str) else k): _normalise_value(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_normalise_value(v) for v in value]
    return value


def _to_rego_input_json(value: object) -> str:
    """Serialize evaluation input for embedding in a regopy query.

    Non-ASCII is emitted as raw UTF-8 (``ensure_ascii=False``): with the
    default, ``₦`` would reach rules as the six characters ``\\u20a6`` and
    Arabic or Amharic text would be unmatchable. See ``_CONTROL_MAP`` for how
    control characters are handled.

    Known residual limitation: ``"`` and ``\\`` must still be escaped in JSON,
    and regopy keeps the escape. regopy stores the same characters in pack
    and config literals the same way, so equality, ``contains`` and regex
    checks stay consistent; only length-based checks (``count``) see one
    extra character per quote or backslash.
    """
    return json.dumps(_normalise_value(value), ensure_ascii=False)


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
        signing_key: bytes | str | None = None,
        config: dict | None = None,
    ) -> None:
        self._packs = packs
        self._cache = cache
        self._config: dict = config or {}
        self._signer: ReceiptSigner | None = None
        if signing_key is not None:
            from ..receipts._signer import ReceiptSigner
            self._signer = ReceiptSigner(signing_key)
        self._keep_chars = _non_ascii_chars(
            [p.rego_source for p in packs]
            + [src for _, src in _build_config_modules(self._config)]
        )

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

        rego_input = input.to_rego_input()
        if isinstance(rego_input.get("output"), str):
            rego_input["output"] = _fold_non_ascii(rego_input["output"], self._keep_chars)
        input_json = _to_rego_input_json(rego_input)

        if self._config:
            # Config makes the interpreter unique — skip shared cache
            interp = _build_interpreter(self._packs, self._config)
        elif self._cache:
            interp = _get_interpreter(self._packs)
        else:
            interp = _build_interpreter(self._packs)

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
                pv = {p.id: p.version for p in self._packs if any(d.pack == p.id for d in result.decisions)}
                token = self._signer.sign(result, input.action, input.params, input.output, input.context, pack_versions=pv, decided_by="opa_native")
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
            pv = {p.id: p.version for p in self._packs if any(d.pack == p.id for d in result.decisions)}
            token = self._signer.sign(result, input.action, input.params, input.output, input.context, pack_versions=pv)
            result = result.model_copy(update={"receipt_token": token})
        return result

    def _evaluate_individually(self, input_json: str) -> ComplianceResult:
        """Fallback: evaluate each pack with its own interpreter."""
        decisions: list[PolicyDecision] = []
        for pack in self._packs:
            interp = _build_interpreter([pack], self._config or None)

            q_d = f"d := {pack.query_prefix}.decision"
            b = _query(interp, input_json, q_d)

            messages: list[str] = []
            rule_keys: list[str] = []
            if "d" not in b:
                # A pack that yields no decision is broken for this input.
                # Fail closed: never let an evaluation failure read as "allow".
                action: Action = "escalate"
                messages = [(
                    f"comply54: policy pack {pack.id} produced no decision for this "
                    "input; failing closed for human review"
                )]
            else:
                action = b["d"]
            if action != "allow" and "d" in b:
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
