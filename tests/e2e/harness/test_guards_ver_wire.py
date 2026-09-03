"""Structural guard — every RAMP body this harness sends carries `ver`, from the SDK.

The Go services have guards holding their senders to the protocol's rule that
`ver` is stamped from a single constant and never a literal. None of them can
open a `.py` file, and this harness is a sender: it plays the agent, the broker
client and the publisher against a live stack. Several of its builders shipped an
empty or hand-written protocol version and nothing noticed -- no service
validates `ver`, and the two that read it echo it straight back, so a wrong value
never surfaces as a rejection. That is the same blindness that let a "0.3"
builder survive on the Go side long enough to be filed as a release blocker.

Two offences, from the same walk: a request body with no ``"ver"`` key at all,
and a ``"ver"`` whose value is written by hand rather than taken from
``ramp_sdk.ProtocolVersion``.

Scope comes from the contract, not from a guess
-----------------------------------------------
The first version of this guard recognised a body by a hand-picked key pair --
``requester`` or ``idempotency_key`` beside ``uris``, ``items`` or ``entries``.
That matched DiscoverResources and ExecuteTransaction and nothing else, so
ReportUsage, PushResources, Register and the broker resolve body were all outside
it: four of the six RPC families this harness drives, and one live sender that
shipped no ``ver`` at all sat under it unreported.

Scope is now derived the way the Go omission guard derives its own -- from the
generated types, which are already a pinned dependency of this harness. Every
generated model that declares a ``ver`` field is read, the request models are
kept, and their field names become the markers below. A message added to the
protocol tomorrow is covered the day a builder for it is written, with no edit
here.

Two arms, because a body is not always finished where it starts
---------------------------------------------------------------
A dict literal is recognised when its keys carry two markers, or one marker that
belongs to exactly one request model. The second arm is what sees a Register
body, whose only distinguishing key is ``registration_data``.

A name a sub-message also carries is demoted rather than dropped. ``items`` is the
case that forced the distinction: it is the ExecuteTransaction body's only
distinguishing key, and the payload the agent signs over its ordered request set
spells it too. Dropping every such name left that body matched by ``requester``
alone -- which DiscoveryRequest carries as well -- so the guard stopped seeing it.
Promoting them back is worse: ``domain`` and ``reason`` are request fields too, and
they sit on error details this harness reads back by the dozen. So a demoted name
corroborates a marker already present and is never the first witness.

Keys assigned afterwards count too. ``broker_client._canonical_resolve_body``
opens with a literal that carries only ``requester`` and adds ``uris`` on the
next statement; read the literal alone and the builder is invisible. So the
literal's keys are unioned with every ``name["k"] = ...`` store on the name it
was bound to. That union is module-wide rather than scope-aware, which can only
ever add keys and so only ever widens what the guard looks at.

The degenerate bodies in the signature suites -- an EMPTY ``requester`` beside
``uris``, proving a request is refused before its contents are read -- are held
to the rule like any other. They are still sent, and stamping them changes
nothing about what they prove: the signature check runs before the body is
parsed.

The scan is AST-based, which is what lets it read its own siblings safely --
``test_guards_single_offer_wire`` holds ``"ver": "1.0"`` inside snippet STRINGS,
which a regex would flag and a parse correctly sees as a string constant. It
still excludes itself, because its own meta-cases spell both offences.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from wire import models as wire_models
from wire.base import WireModel

from .ast_scan import dict_string_keys, scan_tree

# The name every stamped site imports from ramp_sdk, in both the spellings a
# caller may use: `from ramp_sdk import ProtocolVersion` or `ramp_sdk.ProtocolVersion`.
_SDK_CONSTANT = "ProtocolVersion"
_SDK_MODULE = "ramp_sdk"

# Fields every ver-bearing message carries. They say nothing about WHICH message a
# dict is, so they can never distinguish a body from anything else.
_UNIVERSAL_FIELDS = frozenset({"ver", "ext", "ext_critical"})

# Generated message names that are answers rather than requests. This harness is a
# sender; it builds requests and parses responses, so a dict shaped like a response
# is something it read back, not something it has to stamp.
_RESPONSE_SUFFIXES = ("Response", "Result", "Challenge", "Confirmation")

# The manifest versions the /.well-known/ramp.json DOCUMENT SCHEMA, not the RPC
# envelope. ramp.proto keeps the two namespaces separate and the harness does not
# author manifests, so it is not a request body for this guard's purposes.
_MANIFEST_MESSAGE = "WellKnownManifest"


def _generated_models() -> dict[str, frozenset[str]]:
    """Every generated wire model, by name, with its field names."""
    return {
        name: frozenset(getattr(obj, "model_fields", {}) or {})
        for name, obj in vars(wire_models).items()
        if inspect.isclass(obj) and issubclass(obj, WireModel) and obj is not WireModel
    }


def _request_models(models: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]:
    """The ver-bearing models this harness sends."""
    return {
        name: fields
        for name, fields in models.items()
        if "ver" in fields and name != _MANIFEST_MESSAGE and not name.endswith(_RESPONSE_SUFFIXES)
    }


def _nested_fields(models: dict[str, frozenset[str]]) -> frozenset[str]:
    """Every field name the ver-less messages declare -- the sub-messages, and only those."""
    return frozenset().union(*(fields for name, fields in models.items() if "ver" not in fields))


def _body_markers(models: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]:
    """Field name -> the request models carrying it, for names no sub-message carries.

    What has to be kept out is the NESTED dict: ``{offer, agent_acceptance}`` inside
    ``items[]``, the requester, the usage block. Every one of those is a message with
    no ``ver`` of its own, so a name that appears on the ver-less models and on NO
    request model is dropped. That excludes all of them without naming any.

    A name a request model declares itself is not lost, only demoted -- see
    ``_shared_markers``.

    Response models are deliberately NOT subtracted. Nothing is nested inside a
    request because it appears on a response, and subtracting them cost the
    ExecuteTransaction body its only distinguishing key, ``items``.
    """
    requests = _request_models(models)
    nested = _nested_fields(models)
    owners: dict[str, set[str]] = {}
    for name, fields in requests.items():
        for field in fields - _UNIVERSAL_FIELDS - nested:
            owners.setdefault(field, set()).add(name)
    return {field: frozenset(names) for field, names in owners.items()}


def _shared_markers(models: dict[str, frozenset[str]]) -> frozenset[str]:
    """Request field names a sub-message carries too, so they corroborate and no more.

    ``items``, ``idempotency_key``, ``exchange``, ``domain``, ``reason`` and the rest
    of this set each name a top-level request field AND a field of some message with
    no ``ver``. On its own such a name says nothing: ``{"error": e, "reason": r}`` is
    an edge response this harness asserts on, and the acceptance payload the SDK signs
    carries ``items`` beside ``idempotency_key``. Beside a name only requests use, the
    same key does tell a body apart -- which is how an ExecuteTransaction body,
    ``{requester, idempotency_key, items}``, is recognised at all.
    """
    requests = _request_models(models)
    return (frozenset().union(*requests.values()) & _nested_fields(models)) - _UNIVERSAL_FIELDS


_MARKERS = _body_markers(_generated_models())
# A marker owned by exactly one request model identifies a body on its own.
_UNIQUE_MARKERS = frozenset(f for f, owners in _MARKERS.items() if len(owners) == 1)
# Corroborating names: never the first witness, see _shared_markers.
_SHARED_MARKERS = _shared_markers(_generated_models())


def _keys_assigned_later(tree: ast.AST) -> dict[str, set[str]]:
    """Name -> the string keys stored into it by ``name["k"] = ...`` anywhere in tree."""
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)
            ):
                out.setdefault(target.value.id, set()).add(target.slice.value)
    return out


def _bound_name(tree: ast.AST) -> dict[int, str]:
    """Dict-literal node id -> the name it was assigned to, when it was."""
    out: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out[id(node.value)] = target.id
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.value, ast.Dict)
            and isinstance(node.target, ast.Name)
        ):
            out[id(node.value)] = node.target.id
    return out


def _is_request_body(keys: set[str]) -> bool:
    """True iff a dict with these effective keys is a RAMP request body."""
    marked = keys & set(_MARKERS)
    if len(marked) >= 2 or marked & _UNIQUE_MARKERS:
        return True
    return bool(marked) and bool(keys & _SHARED_MARKERS)


def _ver_value(node: ast.Dict) -> ast.expr | None:
    """The value bound to ``"ver"``, or None when the key is absent."""
    for key, value in zip(node.keys, node.values, strict=True):
        if isinstance(key, ast.Constant) and key.value == "ver":
            return value
    return None


def _is_sdk_constant(value: ast.expr) -> bool:
    """True for ``ProtocolVersion`` and for the dotted ``ramp_sdk.ProtocolVersion``."""
    if isinstance(value, ast.Name):
        return value.id == _SDK_CONSTANT
    return (
        isinstance(value, ast.Attribute)
        and value.attr == _SDK_CONSTANT
        and isinstance(value.value, ast.Name)
        and value.value.id == _SDK_MODULE
    )


def _offences(tree: ast.AST) -> list[tuple[int, str]]:
    """Every request body in ``tree`` that omits ``ver`` or writes it by hand.

    THE detector: the tree scan and every meta-test call this one function, so a
    break in the traversal turns the meta-tests red with it rather than leaving
    them green over a private copy.
    """
    later = _keys_assigned_later(tree)
    bound = _bound_name(tree)
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = dict_string_keys(node)
        name = bound.get(id(node))
        if not _is_request_body(keys | later.get(name, set()) if name else keys):
            continue
        value = _ver_value(node)
        if value is None:
            hits.append((node.lineno, "no ver key"))
        elif isinstance(value, ast.Constant):
            hits.append((node.lineno, f"hardcoded ver {value.value!r}"))
        elif not _is_sdk_constant(value):
            hits.append((node.lineno, f"ver is {ast.unparse(value)}, not ProtocolVersion"))
    return hits


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_every_ramp_body_stamps_ver_from_the_sdk() -> None:
    assert _MARKERS, (
        "no request-body marker fields were derived from the generated wire models — "
        "the scan below would pass over nothing, so this is a failure, not a skip"
    )
    hits = scan_tree(_offences, exclude=Path(__file__))
    assert not hits, (
        f"Found {len(hits)} RAMP request body/bodies in tests/e2e/ that do not stamp "
        f"ver from ramp_sdk.ProtocolVersion. A sender MUST stamp it from a single "
        f"constant, and no service validates it on the way in, so a wrong or missing "
        f"value is invisible at run time:\n  " + "\n  ".join(hits)
    )


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_the_marker_set_is_derived_from_the_generated_models() -> None:
    """The scope is the contract's, and covers every RPC family this harness drives.

    Pins the derivation rather than the exact marker list: a protocol change may
    add or rename fields, and this must keep working when it does. What it does
    pin is that each family's distinguishing key still marks a body in one tier or
    the other, since losing one silently returns the guard to the blind spot it was
    rewritten out of. Which tier a key lands in is not pinned here -- ``items``
    moved to the corroborating tier the day the request-set acceptance payload was
    added -- so the meta-cases below are what hold each family's body reportable.
    """
    models = _generated_models()
    assert "ver" in models[_MANIFEST_MESSAGE], "the manifest is expected to carry ver"
    assert _MANIFEST_MESSAGE not in _request_models(models), (
        "the manifest versions the well-known document schema, a separate namespace"
    )
    markers = _MARKERS.keys() | _SHARED_MARKERS
    for family_key in ("uris", "items", "usage", "entries", "registration_data"):
        assert family_key in markers, f"{family_key} must mark a body"


_MISSING = """
body = {"requester": {"id": a}, "uris": [u]}
"""

_HARDCODED = """
body = {"ver": "1.0", "requester": {"id": a}, "uris": [u]}
"""

_STAMPED = """
body = {"ver": ProtocolVersion, "requester": {"id": a}, "uris": [u]}
"""

_STAMPED_DOTTED = """
body = {"ver": ramp_sdk.ProtocolVersion, "requester": {"id": a}, "uris": [u]}
"""

# One per RPC family the first matcher could not see. Each was a live builder
# whose stamp could be deleted with the suite still passing.
_USAGE_REPORT_MISSING = """
body = {"idempotency_key": k, "transaction_id": t, "usage": {"consumed_quantity": 0}}
"""

_PUSH_RESOURCES_MISSING = """
payload = {"tenant_id": t, "caller_id": c, "entries": [e]}
"""

_REGISTER_MISSING = """
body = {"registration_data": {"environment": "staging"}}
"""

# The resolve builder: the literal carries no payload key, and the one that makes
# it a body arrives on the next statement.
_BUILD_THEN_MUTATE_MISSING = """
def build(q):
    out = {"id": i, "idempotency_key": k, "requester": r}
    out["uris"] = list(q)
    return out
"""

# The signature suites pair an EMPTY requester with uris on purpose; the guard
# must still hold them to the rule, because they are sent.
_DEGENERATE_STAMPED = """
body = {"ver": ProtocolVersion, "requester": {}, "uris": [u]}
"""

# A per-item dict inside items[] is not a request body: its keys sit on messages
# the harness never stamps, so neither of them is a marker.
_NESTED_ITEM = """
item = {"offer": o, "agent_acceptance": {"signature": s}}
"""

# The ExecuteTransaction body. Its only distinguishing key is `items`, which the
# agent's request-set acceptance payload spells too -- so a marker rule that drops
# every name a sub-message mentions leaves this body unmatched and unreported.
_TRANSACTION_MISSING = """
body = {"requester": r, "idempotency_key": k, "items": [i]}
"""

# That payload. The SDK signs it, the harness never sends it, and no key it carries
# is a marker: `offer_sig`, `requester_id` and `requester_domain` are declared by
# sub-messages alone, and `items` and `idempotency_key` only corroborate.
_REQUEST_ACCEPTANCE_PAYLOAD = """
payload = {
    "items": [{"offer_sig": s, "exchange": e}],
    "requester_id": a,
    "requester_domain": d,
    "idempotency_key": k,
}
"""

# MCP tool arguments are not a RAMP body. `uris` alone is carried by more than one
# request model, so it cannot identify one on its own.
_MCP_TOOL_ARGUMENTS = """
result = call_tool("ramp_discover", {"uris": [uri]})
"""

# A depicted body inside a STRING is source under discussion, not a sender. This
# is the shape test_guards_single_offer_wire holds in its own snippets.
_DEPICTED_IN_A_STRING = '''
SNIPPET = """
body = {"ver": "1.0", "requester": {"id": a}, "uris": [u]}
"""
'''


def _hits(src: str) -> list[tuple[int, str]]:
    return _offences(ast.parse(src))


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_flags_a_body_with_no_ver() -> None:
    assert len(_hits(_MISSING)) == 1


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_flags_a_hardcoded_ver() -> None:
    hits = _hits(_HARDCODED)
    assert len(hits) == 1 and "hardcoded" in hits[0][1]


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_passes_a_body_stamped_from_the_sdk() -> None:
    assert _hits(_STAMPED) == []
    assert _hits(_STAMPED_DOTTED) == []


@pytest.mark.stack_isolation("shared-without-cleanup")
@pytest.mark.parametrize(
    ("family", "src"),
    [
        ("usage_report", _USAGE_REPORT_MISSING),
        ("push_resources", _PUSH_RESOURCES_MISSING),
        ("register", _REGISTER_MISSING),
        ("build_then_mutate_resolve", _BUILD_THEN_MUTATE_MISSING),
    ],
)
def test_guard_flags_the_families_the_first_matcher_was_blind_to(family: str, src: str) -> None:
    """Each of these passed unreported before the scope came from the generated types."""
    assert len(_hits(src)) == 1, f"{family} body must be reported when it omits ver"


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_holds_the_degenerate_signature_bodies_to_the_rule() -> None:
    assert _hits(_DEGENERATE_STAMPED) == []
    assert len(_hits(_DEGENERATE_STAMPED.replace('"ver": ProtocolVersion, ', ""))) == 1


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_ignores_a_nested_item_dict() -> None:
    assert _hits(_NESTED_ITEM) == []


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_flags_a_transaction_body_with_no_ver() -> None:
    """`items` is this body's only marker, and a sub-message spells it too."""
    assert len(_hits(_TRANSACTION_MISSING)) == 1


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_ignores_the_request_acceptance_payload() -> None:
    """It carries `items` beside `idempotency_key`, and neither may witness on its own."""
    assert _hits(_REQUEST_ACCEPTANCE_PAYLOAD) == []


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_ignores_mcp_tool_arguments() -> None:
    assert _hits(_MCP_TOOL_ARGUMENTS) == []


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_ignores_a_body_depicted_inside_a_string() -> None:
    assert _hits(_DEPICTED_IN_A_STRING) == []
