"""E2E: the MCP account tools across the three-exchange topology.

An agent's account is per-Exchange. This suite drives that through the tools an
agent actually has: a real ``fastmcp`` client speaks Streamable HTTP to the
identity service's ``/mcp`` endpoint, and every call below is signed on the
agent's behalf with a key the identity service custodies.

EVERY TEST TAKES ``seeded`` AND NO BODY READS IT. The parameter is what runs the
ingest, and the ingest is what creates the tenant rows the exchanges look up.
A registration is refused when the tenant named by ``EXCHANGE_DEFAULT_TENANT``
has no row, so a reader who deletes the parameter as unused gets a stack that
never seeds and five ``ramp_register`` calls failing on a precondition far from
the cause. It stays in every signature for that reason.

WHAT THE STACK PUBLISHES. exchange-b and exchange-c are configured with a
registration schema and a terms revision; exchange-a publishes neither. Both
contracts are therefore exercised against real services rather than a double: an
exchange that asks for specific details, and one that asks for nothing in
particular and takes the payload as it comes.

ONE AGENT, NOT ONE PER TEST. Sign-up drives a fixed account in the stack's
Zitadel, so ``provision_agent`` returns the same subdomain every time and every
test here acts as the same agent. Its registrations therefore accumulate across
the suite, and they survive a run when the stack is left up. Nothing below
assumes a clean slate at an exchange it registers at: those claims are about a
DIFFERENCE — the state before and after — never about a total.

EXCHANGE-C IS RESERVED, AND NOTHING HERE MAY REGISTER AT IT. That reservation is
what lets three assertions be claims about a TOTAL: that exchange-c answers
"registered false", that no hint names it, and that a refused registration
opened no account there. None of the three can be written as a difference. A
refusal cannot be observed at an exchange the agent already has an account at,
because the exchange's Register is idempotent — a row that already carries a
billing reference takes a fast path and returns the same handle whether or not
the caller's pre-check let the request through, so a before-and-after comparison
stays equal even when the refusal has failed. The reservation is stated again
beside exchange-c's compose block, which is the other place it can be broken.

WHAT THIS SUITE CANNOT SEE, said plainly rather than left to be assumed:

- The ``terms_digest`` a registration echoes is not observable from outside. The
  exchange stores it, but no RPC returns it, so nothing here can read it back.
  The echo is asserted in the Go integration suite, which reads the stored value
  through the exchange's own repository.
- A payload refused against exchange-b's schema is refused by the IDENTITY
  ADAPTER's pre-check, not by exchange-b. The exchange enforces the same schema,
  but the adapter checks first and never signs the call, so the request does not
  reach the exchange — "the registration was refused" here is a claim about the
  adapter and is written that way.
"""

from __future__ import annotations

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.client import CallToolResult
from fastmcp.exceptions import ToolError

from .conftest import StackURLs
from .seed import SeededFixture
from .exchanges import (
    EXCHANGE_A_DOMAIN,
    EXCHANGE_B_DOMAIN,
    EXCHANGE_C_DOMAIN,
    exchange_url,
)

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

# The two source markers ramp_status puts on every entry. An agent reads this
# field first, because it decides how much the rest of the entry is worth.
_FROM_EXCHANGE = "exchange"
_FROM_LOCAL_HINT = "local_hint"


def _published_requirements(stack: StackURLs, domain: str) -> dict:
    """The registration schema ``domain`` publishes, read from its own manifest.

    DERIVED rather than restated from the compose file, and that is the point:
    the tool description tells an agent to read the schema out of the exchange's
    /.well-known/ramp.json and send members that match, so this suite does what
    it tells the agent to do. A copy of the schema here would still pass if the
    exchange stopped publishing one.
    """
    manifest = httpx.get(f"{exchange_url(stack, domain)}/.well-known/ramp.json", timeout=10.0)
    manifest.raise_for_status()
    block = manifest.json().get("account_registration") or {}
    schema: dict = block.get("data_schema") or {}
    assert schema, f"{domain} publishes no registration schema: {manifest.json()}"
    return schema


def _fields_for(schema: dict) -> dict[str, str]:
    """A payload satisfying every member ``schema`` requires.

    The MEMBERS come from the schema's own ``required`` list, so a member the
    schema stops asking for is dropped without an edit here. The VALUES are a
    fixed table: nothing reads the properties block, ``minLength`` or the email
    pattern, because a value can satisfy a constraint only if someone wrote one
    that does.

    So a schema that GAINS a required member fails the suite at the assertion
    below, naming the member, before anything is sent. That is the intended
    behaviour and not a gap — the alternative is inventing a value and sending a
    payload nobody chose — but it is the opposite of what a reader would assume
    from "built from the schema", so it is stated rather than implied.
    """
    values = {
        "company_name": "Stoa Press",
        "billing_email": "billing@stoa.example",
        "vat_id": "DE811234567",
    }
    required = schema.get("required") or []
    missing = [member for member in required if member not in values]
    assert not missing, f"the suite has no value for required members {missing}"
    return {member: values[member] for member in required}


def _entries(result: CallToolResult) -> list[dict]:
    """The account entries a ramp_status result carries."""
    payload = result.structured_content
    assert payload is not None, "status returned no structured content"
    assert "accounts" in payload, f"status returned no account list: {payload}"
    accounts: list[dict] = payload["accounts"]
    return accounts


async def _hint_domains(client: Client) -> set[str]:
    """Every exchange the agent's own note list names.

    Extracted beside the other two readers rather than written per call site: the
    same set expression appeared four times in two layouts, so a grep for one
    spelling found half of them.
    """
    return {entry["exchange"] for entry in _entries(await client.call_tool("ramp_status", {}))}


def _entry_for(entries: list[dict], domain: str) -> dict:
    """The single entry naming ``domain``, or a failure saying what was there."""
    matching = [entry for entry in entries if entry.get("exchange") == domain]
    assert len(matching) == 1, f"want exactly one entry for {domain}, got {entries}"
    return matching[0]


async def test_register_and_status_across_three_exchanges(
    compose_stack: StackURLs,
    seeded: SeededFixture,
    mcp_bearer: str,
) -> None:
    """One agent, accounts at two of three exchanges, both status modes.

    The whole point of the account tools taking a target: before this an agent
    could only ever reach the one exchange the deployment configured.
    """
    schema = _published_requirements(compose_stack, EXCHANGE_B_DOMAIN)

    async with Client(f"{compose_stack.identity}/mcp", auth=mcp_bearer) as client:
        # exchange-a publishes no schema, so it asks for nothing in particular and
        # takes the payload as it comes — the behaviour every exchange had before
        # the block existed.
        registered_a = await client.call_tool(
            "ramp_register",
            {"exchange": EXCHANGE_A_DOMAIN, "fields": {"company_name": "Stoa Press"}},
        )
        # exchange-b does publish one, and the fields come from what it published.
        registered_b = await client.call_tool(
            "ramp_register",
            {"exchange": EXCHANGE_B_DOMAIN, "fields": _fields_for(schema)},
        )

        handles = {}
        for domain, result in (
            (EXCHANGE_A_DOMAIN, registered_a),
            (EXCHANGE_B_DOMAIN, registered_b),
        ):
            out = result.structured_content
            assert out is not None, f"register at {domain} returned no structured content"
            assert out.get("exchange") == domain, f"register at {domain} answered {out}"
            assert out.get("billing_ref"), f"register at {domain} minted no handle: {out}"
            handles[domain] = out["billing_ref"]

        # Each exchange minted its OWN handle. An account is per-exchange, so two
        # registrations that came back with one handle would mean the calls landed
        # on the same service.
        assert handles[EXCHANGE_A_DOMAIN] != handles[EXCHANGE_B_DOMAIN], (
            "both registrations returned the same account handle"
        )

        # Asked directly, each exchange answers for itself. exchange-c is this
        # suite's reserved never-registered target (see the module docstring), so
        # "registered false" here is a claim about a total and holds only for as
        # long as that reservation does.
        for domain, want_registered in (
            (EXCHANGE_A_DOMAIN, True),
            (EXCHANGE_B_DOMAIN, True),
            (EXCHANGE_C_DOMAIN, False),
        ):
            entry = _entry_for(
                _entries(await client.call_tool("ramp_status", {"exchange": domain})), domain
            )
            assert entry["source"] == _FROM_EXCHANGE, entry
            assert entry["registered"] is want_registered, (
                f"{domain} reports registered={entry['registered']}, want {want_registered}: {entry}"
            )
            assert entry["as_of"], entry

        # Asked with no exchange, the answer is the local note of where this
        # adapter registered the agent — the two it did, and not the one it did
        # not.
        hints = _entries(await client.call_tool("ramp_status", {}))

    named = {entry["exchange"] for entry in hints}
    # Presence and absence rather than an exact set: the agent is shared across
    # this suite, so a future test registering somewhere else must not fail this
    # one. What is claimed here is that the two registrations left notes, and
    # that the reserved never-registered exchange did not.
    assert {EXCHANGE_A_DOMAIN, EXCHANGE_B_DOMAIN} <= named, f"the hint list is {hints}"
    assert EXCHANGE_C_DOMAIN not in named, (
        f"a hint names {EXCHANGE_C_DOMAIN}, where this agent never registered: {hints}"
    )
    for entry in hints:
        assert entry["source"] == _FROM_LOCAL_HINT, entry
        # A hint asked nobody, so it reports no account state.
        assert entry["active"] is None, entry
        assert entry["billing_ref"] == "", entry


async def test_both_status_modes_carry_the_same_entry_shape(
    compose_stack: StackURLs,
    seeded: SeededFixture,
    mcp_bearer: str,
) -> None:
    """One schema, no branching — asserted on what the wire actually carried.

    Two shapes from one tool would make an agent branch on which arguments it
    passed to know how to read the answer. Compared as MEMBER SETS rather than
    through a model, because a model quietly supplies a member one mode omitted,
    which is exactly the drift under test.
    """
    async with Client(f"{compose_stack.identity}/mcp", auth=mcp_bearer) as client:
        await client.call_tool(
            "ramp_register",
            {"exchange": EXCHANGE_A_DOMAIN, "fields": {"company_name": "Stoa Press"}},
        )
        named = _entry_for(
            _entries(await client.call_tool("ramp_status", {"exchange": EXCHANGE_A_DOMAIN})),
            EXCHANGE_A_DOMAIN,
        )
        hint = _entry_for(_entries(await client.call_tool("ramp_status", {})), EXCHANGE_A_DOMAIN)

    assert set(named) == set(hint), (
        f"the two modes carry different members:\n  exchange: {sorted(named)}\n  hint:     {sorted(hint)}"
    )
    assert named["source"] != hint["source"], (
        f"both modes marked their entry {named['source']!r}; the marker is what tells them apart"
    )


async def test_an_exchange_domain_is_case_insensitive(
    compose_stack: StackURLs,
    seeded: SeededFixture,
    mcp_bearer: str,
) -> None:
    """One Exchange, whichever case the agent writes it in.

    Domain names are case-insensitive and every other party already treats them
    that way: the identity service's allowlist lowercases before comparing, and
    the receiving exchange lowercases the host before checking the audience its
    signature claims. So a mixed-case call is accepted end to end.

    The local note is what a second spelling used to break. Its key carries the
    exchange as plain text, so registering as EXCHANGE-B added a note no later
    call could find, ask after or delete: the hint list named the same exchange
    twice, "no account here" could not remove either one, and sixty-four
    variants of one domain would fill the agent's whole budget.

    Asserted as a DIFFERENCE, and this test opens the account that difference is
    measured against rather than inheriting one from whichever sibling ran first.
    Register is idempotent, so doing it here costs one round trip and the
    after-equals-before claim still holds.
    """
    upper = EXCHANGE_B_DOMAIN.upper()
    assert upper != EXCHANGE_B_DOMAIN, "the domain has no case to vary, so this proves nothing"

    # Read before the session opens. _published_requirements calls httpx.get,
    # which is synchronous: inside the async block it blocks the event loop for
    # up to its ten-second timeout, so the client's own stream reader cannot run.
    # The two sibling call sites already read the manifest before opening a
    # session.
    fields = _fields_for(_published_requirements(compose_stack, EXCHANGE_B_DOMAIN))

    async with Client(f"{compose_stack.identity}/mcp", auth=mcp_bearer) as client:
        # This test's own precondition. It used to depend on a sibling earlier in
        # the module having registered here, so running this test alone, or under
        # --lf after that sibling failed, failed at the assertion below while the
        # adapter was correct.
        await client.call_tool("ramp_register", {"exchange": EXCHANGE_B_DOMAIN, "fields": fields})

        before = await _hint_domains(client)
        assert EXCHANGE_B_DOMAIN in before, (
            "the registration this test just made did not reach the hint list, so the "
            f"difference below would be measured against nothing: {before}"
        )

        opened = await client.call_tool("ramp_register", {"exchange": upper, "fields": fields})
        echoed = (opened.structured_content or {}).get("exchange")
        assert echoed == EXCHANGE_B_DOMAIN, (
            f"register echoed {echoed!r}; an agent comparing that against a hint would "
            f"see two exchanges where there is one"
        )

        # The other spelling still finds the same account.
        named = _entry_for(
            _entries(await client.call_tool("ramp_status", {"exchange": EXCHANGE_B_DOMAIN})),
            EXCHANGE_B_DOMAIN,
        )
        after = await _hint_domains(client)

    assert named["registered"] is True, f"the account opened as {upper} was not found: {named}"
    assert after == before, (
        f"a second spelling of one exchange left a second note: {after - before}"
    )


async def test_register_is_refused_when_the_payload_misses_a_published_member(
    compose_stack: StackURLs,
    seeded: SeededFixture,
    mcp_bearer: str,
) -> None:
    """The adapter's pre-check, against a schema a real exchange published.

    The refusal is the IDENTITY ADAPTER's. exchange-c enforces this schema too,
    but the adapter pre-checks against it and never signs the call, so the
    request does not reach the exchange and nothing here observes its gate. What
    this does say is that an agent is told which members are wrong, and that no
    account was opened as a result. The exchange-side gate is covered by the Go
    integration suite, which drives it through the Connect surface.

    WHICH LAYER REFUSED IS ASSERTED, not inferred. Once the exchange enforces the
    schema too, every other check here passes whether the adapter pre-checked or
    not: the exchange refuses the same payload, the tool error is rendered
    through the same field-list renderer over the exchange's own field errors,
    both sides compile the same schema with the same validator so the named
    members are identical, and no account is opened either way. Only one sentence
    separates the two paths — the local refusal says the exchange "will not
    accept these fields", and the remote one is built from the failed-call
    wording instead. Asserting that sentence is what keeps this a test of the
    adapter.

    It is worth pinning because the pre-check can turn itself off: the identity
    side compiles the published schema and is left with nothing to check when the
    schema does not compile, and there is no branch for that case.

    IT RUNS AGAINST EXCHANGE-C, and the choice is the assertion. This suite's
    agent is shared, so at exchange-b it already holds an account by the time
    this runs — and the exchange's Register is idempotent, taking a fast path for
    a row that already carries a billing reference and returning the same handle
    whether or not the pre-check let the request through. Comparing exchange-b's
    account before and after would therefore be equal either way: the assertion
    could not fail, and a regression that sent the refused payload would pass it.
    exchange-c is reserved as the exchange nothing here ever registers at, which
    turns "no account was opened" back into a claim that can be false.

    The reservation itself is read BEFORE the refused call rather than assumed,
    the same way the sibling negative below reads it. A broken reservation — some
    earlier test registering at exchange-c — would otherwise surface here as an
    accusation against the adapter.
    """
    schema = _published_requirements(compose_stack, EXCHANGE_C_DOMAIN)
    required = schema.get("required") or []
    assert required, f"exchange-c's schema requires nothing, so nothing can be missing: {schema}"

    async with Client(f"{compose_stack.identity}/mcp", auth=mcp_bearer) as client:
        before = _entry_for(
            _entries(await client.call_tool("ramp_status", {"exchange": EXCHANGE_C_DOMAIN})),
            EXCHANGE_C_DOMAIN,
        )
        assert before["registered"] is False, (
            f"exchange-c is reserved as a never-registered target and something "
            f"registered at it, so this test cannot tell a refusal from a no-op: {before}"
        )

        with pytest.raises(ToolError) as refusal:
            await client.call_tool(
                "ramp_register",
                # Everything the schema requires, left out.
                {"exchange": EXCHANGE_C_DOMAIN, "fields": {"unrelated": "value"}},
            )
        message = str(refusal.value)
        assert "will not accept these fields" in message, (
            f"the refusal did not come from the adapter's local pre-check — only it "
            f"renders that wording, so the payload was signed and sent and this is "
            f"the exchange's own answer: {message}"
        )
        for member in required:
            assert member in message, (
                f"the refusal does not name the missing member {member!r}: {message}"
            )

        after = _entry_for(
            _entries(await client.call_tool("ramp_status", {"exchange": EXCHANGE_C_DOMAIN})),
            EXCHANGE_C_DOMAIN,
        )

    # The exchange's own answer, fetched now. False the moment the refused
    # payload was signed and sent instead.
    assert after["registered"] is False, (
        f"the refused registration opened an account at {EXCHANGE_C_DOMAIN}: {after}"
    )


async def test_register_refuses_an_exchange_that_is_not_a_bare_domain(
    compose_stack: StackURLs,
    seeded: SeededFixture,
    mcp_bearer: str,
) -> None:
    """A URL is not a domain, and the difference is where a signed request goes.

    The endpoint comes from the exchange's own manifest, so a caller that could
    name a URL would choose where its registration is delivered rather than only
    which exchange it is for.

    IT RUNS AGAINST EXCHANGE-C, for the same reason as the sibling negative
    above. Pointed at exchange-a, where this suite's agent registers in its first
    test, the side-effect check cannot fail both ways. If the adapter recorded
    the raw string, the hint set would gain a member and the assertion would
    catch it. But if the adapter normalized the URL to its host, the key would be
    exchange-a's own domain, already in the set, and the assertion would hold
    while the refusal had not happened. exchange-c is the exchange nothing here
    ever registers at, so absence there is a claim that can be false. A refused
    call opens nothing, so the reservation holds.

    The reservation itself is read BEFORE the refused call rather than assumed. A
    broken reservation — some earlier test registering at exchange-c — would
    otherwise surface here as an accusation against the adapter.
    """
    async with Client(f"{compose_stack.identity}/mcp", auth=mcp_bearer) as client:
        before = await _hint_domains(client)
        assert EXCHANGE_C_DOMAIN not in before, (
            f"exchange-c is reserved as a never-registered target and something "
            f"registered at it, so this test cannot tell a refusal from a no-op: {before}"
        )
        with pytest.raises(ToolError) as refusal:
            await client.call_tool(
                "ramp_register",
                {
                    "exchange": f"http://{EXCHANGE_C_DOMAIN}/register",
                    "fields": {"company_name": "Stoa Press"},
                },
            )
        assert "bare domain" in str(refusal.value), str(refusal.value)

        after = await _hint_domains(client)

    assert after == before, f"a refused call left a registration note: {after - before}"
