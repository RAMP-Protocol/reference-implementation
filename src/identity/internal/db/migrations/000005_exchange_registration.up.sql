-- A local note that this service registered an agent at an Exchange. It exists
-- for exactly one reason: to answer ramp_status when the agent names no
-- exchange, so the tool can list the Exchanges this adapter has registered it
-- at without making a network call.
--
-- WHAT IT HOLDS. The Exchange's domain and when the registration was last
-- confirmed, and NOTHING from the submitted registration_data. Those members are
-- the operator's business details — legal entity, billing contact, tax
-- identifiers, whatever a given Exchange asks for — and this adapter neither
-- logs them nor stores them; they pass through it on their way to the Exchange
-- and are not kept. A dump of this table therefore discloses which Exchanges an
-- agent does business with, and nothing whatever about who that operator is.
--
-- One exception, and it is about the OTHER party rather than this table: a
-- refusal an Exchange writes is logged, bounded to 300 bytes, so an Exchange
-- that quotes a submitted value back into its own refusal puts a short value on
-- an operator line. Nothing reaches this table either way. Stated here because
-- this comment is where a reader comes for the whole rule.
--
-- IT IS A HINT, NEVER AN AUTHORITY. The Exchange is the only party that knows
-- whether an account exists: a registration made outside this adapter leaves no
-- row here, and a row can outlive an account the Exchange has closed. That is
-- why ramp_status marks these entries as hints and marks its exchange-scoped
-- answer, which is fetched from the Exchange on the call, as authoritative.
--
-- HOW LONG IT LIVES. As long as the agent's own account record, which the
-- foreign key makes structural rather than a promise: the rows go when the
-- developer account whose subdomain every one of those registrations was signed
-- under goes. There is no agent-deletion flow today; when one is added, this
-- goes with it because it cannot do otherwise.
--
-- HOW MANY THERE ARE. Bounded per agent, at the cap account.MaxExchangeRegistrations
-- states. The exchange column is a value an authenticated agent chooses per call,
-- and with no allowlist configured the key space is the whole DNS namespace — so
-- without a bound this is somewhere a caller can make the table grow, and the
-- status call would add a row without the agent completing a registration at all.
-- Recording past the cap drops that agent's oldest notes, in the same statement
-- as the write. Nothing is lost that cannot be asked for again: a note is a hint,
-- and the next status call against that Exchange rebuilds it.
--
-- registered_at is written by the caller from the injected clock rather than
-- defaulted to now(), so the value a test observes is the one the service chose.
-- It is also what the cap orders by, which is why it is a real timestamp of the
-- last confirmation rather than a flag.
CREATE TABLE identity.exchange_registration (
    subdomain     text        NOT NULL
        REFERENCES identity.developer_account (subdomain) ON DELETE CASCADE,
    exchange      text        NOT NULL,
    registered_at timestamptz NOT NULL,
    CONSTRAINT exchange_registration_pkey PRIMARY KEY (subdomain, exchange)
);
