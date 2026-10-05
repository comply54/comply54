"""
regopy ↔ OPA parity for every regex applied to agent output.

OPA is the reference implementation of Rego (and what agt-policies-nigeria
users run). For every output regex in the bundled packs, and for generated
strings that match it, the in-process engine path must agree with OPA.

Skipped when no ``opa`` binary is on PATH; CI installs one for this test.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from .regex_corpus import generated_examples, output_regex_patterns, regopy_matches

OPA = shutil.which("opa")
# CI sets COMPLY54_REQUIRE_OPA=1 so a missing binary fails instead of skipping.
if OPA is None and os.environ.get("COMPLY54_REQUIRE_OPA") == "1":
    raise RuntimeError("COMPLY54_REQUIRE_OPA=1 but no opa binary on PATH")
pytestmark = pytest.mark.skipif(OPA is None, reason="opa binary not on PATH")

# Strings that stress the engine's input normalisation
_EDGE_CASES = [
    "Patient HIV\nstatus",
    "medical\r\nrecord",
    "national\tid no: 12345678901",
    "ctrl\x13chars\x00here",
    "sending data crossÈborder",
    "رقم قومي 29001011234567",
    "₦15,000,000 transfer",
    'quoted "medical record"',
]


def _opa_matches(items: list[tuple[str, str]], tmp_path) -> list[bool]:
    policy = tmp_path / "parity.rego"
    policy.write_text(
        "package parity\nimport rego.v1\n"
        "r := [regex.match(x[0], lower(x[1])) | some x in input.items]\n"
    )
    data = tmp_path / "input.json"
    data.write_text(json.dumps({"items": items}))
    out = subprocess.run(
        [OPA, "eval", "-d", str(policy), "-i", str(data), "data.parity.r", "--format", "raw"],
        capture_output=True, text=True, check=True,
    )
    results = json.loads(out.stdout)
    assert len(results) == len(items)
    return results


def test_engine_path_agrees_with_opa(tmp_path):
    items = []
    for _, pattern in output_regex_patterns():
        for s in generated_examples(pattern) + _EDGE_CASES:
            items.append((pattern, s))

    opa = _opa_matches(items, tmp_path)
    ours = regopy_matches(items)

    misses = [items[k] for k in range(len(items)) if opa[k] and not ours[k]]
    extras = [items[k] for k in range(len(items)) if ours[k] and not opa[k]]

    assert sum(opa) > len(output_regex_patterns()), "corpus should exercise every pattern"
    assert not misses, f"{len(misses)} cases OPA matches but comply54 misses: {misses[:5]}"
    # The engine maps line breaks to spaces, so `.` may span a former line
    # break. That can only add matches; anything else is a real divergence.
    unexplained = [(p, s) for p, s in extras if not any(c in s for c in "\n\r")]
    assert not unexplained, unexplained[:5]
