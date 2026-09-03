-- Drop the operator's business data from the developer account.
--
-- These four columns existed to serve one caller. A mandatory web form collected
-- a legal entity, a postal address and a jurisdiction during sign-up, wrote them
-- here, and set registration_complete so the flow knew not to ask again. The one
-- thing that ever read them back was the payload an agent's first Exchange
-- registration sent.
--
-- That reader is gone. An agent now names the Exchange it wants an account at
-- and supplies the registration data that Exchange asks for, per Exchange, as
-- that Exchange's published schema describes it. This service fills in nothing on
-- the agent's behalf, so it has no reason to hold the operator's business details
-- and no way to know which of them any given Exchange wants. The form went with
-- the reader; these go with the form.
--
-- registration_complete is dropped for the same reason and not for a different
-- one: it was the form's gate, and a gate in front of nothing is not a record of
-- anything.
--
-- updated_at goes with them, and it is the same shape one step further out. The
-- statement that set it was the form's write, and once that is gone the table has
-- a SELECT and an INSERT and nothing else — no UPDATE anywhere, and no trigger.
-- The column would sit at exactly created_at for every row forever, which is
-- worse than absent: a later query ordering by "last changed" would get an answer
-- that looks right and means nothing. If a mutation is ever added here, adding
-- the column back is one line, and at that point it will record something.
--
-- WHAT THIS DOES NOT DO. DROP COLUMN in Postgres is a catalog change: it marks
-- the column dropped so the planner stops returning it, and leaves the existing
-- row data untouched. The legal entities, addresses and jurisdictions stay in the
-- table's files until every row is rewritten, and they stay in any base backup or
-- WAL segment taken before this ran. Hiding them is not erasing them. The
-- operator runbook carries the one-off rewrite that does erase them, and the
-- retention decision on the older backups. It is not here because it is not a
-- schema step: it waits on the operator deciding this release will not be rolled
-- back, it takes an ACCESS EXCLUSIVE lock that belongs in a maintenance window,
-- and the copies it cannot reach — the older backups, and the register payload an
-- early sign-up forwarded to an Exchange — need decisions a migration cannot make.
-- Frequency is not the reason: a migration file runs once per database, so a
-- rewrite placed here would fire on the boot that first applies this version and
-- never again, against a table that on a fresh database is empty.
--
-- The TABLE stays. It is the durable link between an OIDC identity and the agent
-- subdomain minted for it, and identity.exchange_registration keys its rows to
-- that subdomain with ON DELETE CASCADE, so the notes an agent accumulates hang
-- off this row's lifetime.
ALTER TABLE identity.developer_account
    DROP COLUMN legal_entity,
    DROP COLUMN address,
    DROP COLUMN jurisdiction_country,
    DROP COLUMN registration_complete,
    DROP COLUMN updated_at;
