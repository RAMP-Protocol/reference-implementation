"""Meta-guard — the publisher-jwks entrypoint's WBA entry must match the shared builder.

The publisher-jwks entrypoint renders its Web Bot Auth directory through the
shared builder ``scripts/lib/ed25519_keys.py`` (the image copies it in and the
heredoc imports it from the lib dir passed as argv). That wiring is exactly
what this guard exercises: it lifts the python heredoc out of
``deploy/publisher-jwks/entrypoint.sh`` verbatim, runs it against a synthetic
key file with the in-repo ``scripts/lib`` as the lib dir, and compares the WBA
entry it serves member-for-member against ``wba_directory_key`` fed the same
key and window. It fails loudly if the heredoc is restructured past the
extraction, if the lib-dir argv wiring breaks, or if anyone re-introduces a
hand-written entry that drifts from the shared shape. Validity-window POLICY
(lifetime, skew) stays per-issuer on purpose; the shape and the encoding of
the entry are what may never drift.

Pure subprocess work: no stack, no Docker, no database. The marks come from
``guard_harness.guard_marks``, whose docstring says why the isolation one is
there.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .conftest import REPO_ROOT
from .guard_harness import GATE_TIMEOUT, guard_marks

_ENTRYPOINT = REPO_ROOT / "deploy" / "publisher-jwks" / "entrypoint.sh"
_BUILDER = REPO_ROOT / "scripts" / "lib" / "ed25519_keys.py"

pytestmark = guard_marks(skip_when=not (_ENTRYPOINT.is_file() and _BUILDER.is_file()))


def _load_builder():
    """Import scripts/lib/ed25519_keys.py by path (it is not a package)."""
    spec = importlib.util.spec_from_file_location("ed25519_keys", _BUILDER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _entrypoint_heredoc() -> str:
    """The python program embedded in the entrypoint, lifted verbatim.

    Extraction failing is itself a finding: it means the entrypoint was
    restructured and this guard is no longer reading the code that runs in the
    container — fail loudly rather than passing against nothing.
    """
    text = _ENTRYPOINT.read_text()
    m = re.search(r"<<'PY'\n(.*?)\nPY\n", text, re.DOTALL)
    assert m, (
        "could not find the <<'PY' heredoc in the publisher-jwks entrypoint — "
        "the rendering moved; fix this guard's extraction so it keeps reading "
        "the real code"
    )
    return m.group(1)


def _render(
    tmp_path: Path, key_members: dict, env: dict | None = None
) -> subprocess.CompletedProcess:
    """Run the lifted heredoc against a key file built from key_members."""
    key_file = tmp_path / "publisher-key.json"
    key_file.write_text(json.dumps(key_members))
    program = tmp_path / "entrypoint-render.py"
    program.write_text(_entrypoint_heredoc())
    return subprocess.run(
        [
            sys.executable,
            str(program),
            str(key_file),
            str(tmp_path / "ramp.json"),
            "",
            "ROLE_PUBLISHER",
            str(_BUILDER.parent),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=GATE_TIMEOUT,
        env={**os.environ, **(env or {})},
    )


def test_missing_issuer_refuses_render(tmp_path: Path) -> None:
    """The issuer guard's refusal branch, seen actually refusing.

    A key file with no ``issuer`` and no ``MANIFEST_DOMAIN_OVERRIDE`` must
    abort the render (container start) with the message that names the fix —
    never fall back to guessing the domain from the kid, which would silently
    truncate a dotted identity. Every stack fixture carries ``issuer`` (the
    key-gen scripts stamp and backfill it), so without this test the refusal
    branch would never run anywhere.
    """
    builder = _load_builder()
    seed_b64, pub_b64 = builder.generate_seed_pub_b64()
    proc = _render(
        tmp_path,
        {"kid": "publisher.example", "private_key": seed_b64, "public_key": pub_b64},
        env={"MANIFEST_DOMAIN_OVERRIDE": ""},
    )
    assert proc.returncode != 0, (
        f"render with no issuer succeeded; it must refuse.\nstdout: {proc.stdout}"
    )
    assert "carries no 'issuer'" in proc.stderr, (
        f"refusal did not name the missing member:\nstderr: {proc.stderr}"
    )
    assert not (tmp_path / "http-message-signatures-directory").exists(), (
        "the refusal must not leave a served directory behind"
    )


def test_domain_override_substitutes_for_issuer(tmp_path: Path) -> None:
    """MANIFEST_DOMAIN_OVERRIDE is the documented escape from the issuer guard."""
    builder = _load_builder()
    seed_b64, pub_b64 = builder.generate_seed_pub_b64()
    proc = _render(
        tmp_path,
        {"kid": "publisher.example", "private_key": seed_b64, "public_key": pub_b64},
        env={"MANIFEST_DOMAIN_OVERRIDE": "publisher.example"},
    )
    assert proc.returncode == 0, (
        f"render with MANIFEST_DOMAIN_OVERRIDE failed:\nstderr: {proc.stderr}"
    )
    manifest = json.loads((tmp_path / "ramp.json").read_text())
    assert manifest["domain"] == "publisher.example"


def test_entrypoint_wba_entry_matches_shared_builder(tmp_path: Path) -> None:
    builder = _load_builder()
    seed_b64, pub_b64 = builder.generate_seed_pub_b64()
    key_file = tmp_path / "publisher-key.json"
    key_file.write_text(
        json.dumps(
            {
                "kid": "publisher.example",
                "issuer": "publisher.example",
                "private_key": seed_b64,
                "public_key": pub_b64,
            }
        )
    )
    program = tmp_path / "entrypoint-render.py"
    program.write_text(_entrypoint_heredoc())
    manifest_path = tmp_path / "ramp.json"

    proc = subprocess.run(
        [
            sys.executable,
            str(program),
            str(key_file),
            str(manifest_path),
            "",
            "ROLE_PUBLISHER",
            str(_BUILDER.parent),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=GATE_TIMEOUT,
    )
    assert proc.returncode == 0, (
        f"entrypoint rendering failed:\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    )

    served = json.loads((tmp_path / "http-message-signatures-directory").read_text())
    assert len(served["keys"]) == 1, served
    entry = served["keys"][0]

    # Same key, same window the entrypoint chose — the comparison pins the
    # SHAPE (member set, static values, x encoding), not the window policy.
    expected = builder.wba_directory_key(
        pub_b64, entry.get("not_before", ""), entry.get("not_after", "")
    )
    assert entry == expected, (
        "the publisher-jwks entrypoint and scripts/lib/ed25519_keys.py "
        "wba_directory_key no longer render the same WBA directory entry — "
        f"entrypoint: {json.dumps(entry, sort_keys=True)}\n"
        f"builder:    {json.dumps(expected, sort_keys=True)}"
    )
