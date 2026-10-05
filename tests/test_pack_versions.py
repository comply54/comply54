"""
Pack versions must match between the Python and TypeScript SDKs.

Both embed pack versions in signed receipts (c54_pack_versions). If they
disagree, receipts from the two SDKs report different versions of the same
policy, which breaks cross-SDK audit consistency.
"""

from __future__ import annotations

import re
from pathlib import Path

from comply54.core import packs as P

VERSIONS_TS = Path(__file__).resolve().parent.parent / "packages" / "core" / "src" / "packs" / "versions.ts"


def _ts_versions() -> dict[str, str]:
    return dict(re.findall(r'^\s*"([a-z0-9\-/]+)":\s*"([0-9]+\.[0-9]+\.[0-9]+)"', VERSIONS_TS.read_text(), re.MULTILINE))


def _py_versions() -> dict[str, str]:
    return {v.id: v.version for v in vars(P).values() if isinstance(v, P.PackSpec)}


def test_every_python_pack_has_matching_typescript_version():
    ts, py = _ts_versions(), _py_versions()
    mismatches = {pid: (ver, ts.get(pid)) for pid, ver in py.items() if ts.get(pid) != ver}
    assert not mismatches, f"python vs typescript pack versions differ: {mismatches}"


def test_typescript_lists_no_unknown_packs():
    unknown = set(_ts_versions()) - set(_py_versions())
    assert not unknown, unknown
