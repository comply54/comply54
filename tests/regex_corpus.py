"""
Shared helpers for the regopy compatibility and OPA parity tests.

comply54 evaluates Rego in-process with regopy (rego-cpp), which differs from
OPA in ways that silently disable rules:

  - the ``(?i)`` inline flag makes regex builtins return undefined;
  - escape sequences in string literals are never decoded;
  - its regex engine is byte-oriented, so ``.``, ``\\S`` and negated classes
    consume one byte of a multi-byte UTF-8 character;
  - its output parser crashes on raw control characters.

The packs and ``comply54.core.engine`` work around all four. These helpers
find every regex in the bundled packs and generate strings that match each
one under RE2 (OPA) semantics, so tests can prove the rules actually fire.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from regopy import Interpreter

from comply54.core.engine import _fold_non_ascii, _non_ascii_chars, _to_rego_input_json

PACKS_DIR = Path(__file__).resolve().parent.parent / "comply54" / "packs"

# regex.<fn>(`pattern`, <subject>): patterns are always raw (backtick) strings
REGEX_CALL = re.compile(r"regex\.(\w+)\(\s*`([^`]*)`\s*,\s*(\w+\([^()]*\)|[^,()\s]+)\s*[,)]")
BACKTICK = re.compile(r"`([^`]*)`")


def pack_files() -> list[Path]:
    return sorted(PACKS_DIR.rglob("*.rego"))


@lru_cache(maxsize=1)
def regex_calls() -> tuple[tuple[str, str, str, str], ...]:
    """(file, builtin, pattern, subject) for every regex call in every pack."""
    out = []
    for f in pack_files():
        for fn, pattern, subject in REGEX_CALL.findall(f.read_text(encoding="utf-8")):
            out.append((f.name, fn, pattern, subject.strip()))
    return tuple(out)


def output_regex_patterns() -> list[tuple[str, str]]:
    """(file, pattern) for every regex applied to lower(input.output)."""
    return [(f, p) for f, _, p, s in regex_calls() if s == "lower(input.output)"]


@lru_cache(maxsize=1)
def keep_chars() -> frozenset[str]:
    return _non_ascii_chars([f.read_text(encoding="utf-8") for f in pack_files()])


# ── RE2 → Python translation for example generation ────────────────────────
# Python's \s, \d and \w are Unicode-aware; RE2's are ASCII-only. `.` is
# widened to ASCII plus Latin, Arabic and Ethiopic so examples also exercise
# the non-ASCII handling.
_CLASS = {"s": " \\t\\n\\f\\r", "d": "0-9", "w": "A-Za-z0-9_"}
_DOT = "[\\x20-\\x7e\\u00c0-\\u024f\\u0600-\\u06ff\\u1200-\\u137f]"


def re2_for_python(pattern: str) -> str:
    out: list[str] = []
    i, in_class = 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            n = pattern[i + 1]
            if n in _CLASS:
                out.append(_CLASS[n] if in_class else "[" + _CLASS[n] + "]")
            else:
                out.append(c + n)
            i += 2
            continue
        if in_class:
            if c == "]" and out and out[-1] not in ("[", "[^"):
                in_class = False
            out.append(c)
        elif c == "[":
            in_class = True
            if pattern[i + 1:i + 2] == "^":
                out.append("[^")
                i += 2
                continue
            out.append(c)
        elif c == ".":
            out.append(_DOT)
        else:
            out.append(c)
        i += 1
    return "".join(out)


def generated_examples(pattern: str, n: int = 12) -> list[str]:
    """Strings matching `pattern` under RE2 semantics, in several cases.

    Patterns are lowercase and applied to lower(input.output), so generation
    uses IGNORECASE and each example is returned as-is, UPPER and Title case.
    """
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st

    translated = re.compile(re2_for_python(pattern), re.IGNORECASE)
    got: list[str] = []

    @settings(max_examples=n, database=None, derandomize=True,
              suppress_health_check=list(HealthCheck), deadline=None)
    @given(st.from_regex(translated, fullmatch=False))
    def collect(s: str) -> None:
        got.append(s)

    collect()
    out: set[str] = set()
    for s in got:
        out.update({s, s.upper(), s.title()})
    return sorted(out)


# ── Evaluation exactly as Comply54Engine performs it ─────────────────────────

_MATCH_MODULE = (
    "package parity\nimport rego.v1\n"
    "r := [regex.match(x[0], lower(x[1])) | some x in input.items]\n"
)


def regopy_matches(items: list[tuple[str, str]]) -> list[bool]:
    """regex.match(pattern, lower(text)) via the engine's input path."""
    keep = keep_chars()
    interp = Interpreter()
    interp.add_module("parity", _MATCH_MODULE)
    out: list[bool] = []
    for k in range(0, len(items), 2000):
        chunk = [[p, _fold_non_ascii(s, keep)] for p, s in items[k:k + 2000]]
        raw = str(interp.query(f"input := {_to_rego_input_json({'items': chunk})}; r := data.parity.r"))
        results = json.loads(raw)["bindings"]["r"]
        # An undefined regex.match drops its element from the comprehension
        # instead of yielding false, so a short list means a silently dead rule.
        assert len(results) == len(chunk), (
            f"regopy returned {len(results)} results for {len(chunk)} items: "
            "at least one pattern evaluated to undefined"
        )
        out.extend(results)
    return out
