-- Restores the columns. It does not restore their contents, and it does not
-- restore their positions.
--
-- CONTENTS. A rollback cannot bring them back: the queries that read them are
-- gone, DROP COLUMN stopped the planner returning them, and nothing else in this
-- service holds a copy. Every restored row therefore comes back at the column
-- defaults.
--
-- The Exchange is a separate question, and the answer depends on when the account
-- was opened. For an account opened since the account tools started taking an
-- Exchange argument, the Exchange's record carries what the AGENT submitted to
-- that Exchange: a different submission, by a different party, at a different
-- time. It looks like a backup and is not one. For an account opened before that,
-- this service built the register payload out of these very columns and sent it,
-- so the Exchange's record IS a forwarded copy — legal_entity and
-- jurisdiction_country in typed columns of sor.agent_accounts, and address under
-- that table's extra JSONB. Neither case makes the Exchange a place to restore
-- from. The second one makes it a place an erasure request has to reach.
--
-- updated_at is the exception: it comes back defaulting to now(), so every
-- existing row reads as having changed at rollback time rather than at the time
-- it was actually written. Nothing reads the column today, which is why it was
-- dropped, but an operator should know the restored value is the rollback's
-- clock and not history.
--
-- The one to plan around is registration_complete: it comes back false, so a
-- rolled-back binary reads every existing developer as one that has not yet
-- completed the sign-up form that column gated, and sends them all through it
-- again. That is re-fillable, and it is the safe direction to fail, but an operator
-- should not meet it for the first time during a rollback.
--
-- POSITIONS. ADD COLUMN appends, and Postgres cannot reorder, so all five come
-- back after created_at rather than around it. That is cosmetic. Every generated
-- query names each column explicitly in its SELECT list and in its RETURNING
-- clause, and Postgres returns columns in the order the query names them, so no
-- scan depends on where a column physically sits.
--
-- ORDER. Applying the up migration needs no sequencing: the service runs its own
-- migrations at start-up before it listens, and it runs one replica, so deploying
-- the binary and dropping the columns are one action and no old binary is ever
-- left querying the new schema.
--
-- Going backwards is the case to know about. Start the previous tag after 000006
-- has applied and every developer read asks for columns the planner no longer
-- returns, so every sign-in fails. This file is what would repair that, but
-- nothing runs it: down files ship inside the image and stay there. Reversing
-- 000006 is an escalation, not a step an operator runs by hand.
--
-- This is not a partial recovery that someone finishes by hand afterwards. It is
-- the whole recovery.
ALTER TABLE identity.developer_account
    ADD COLUMN legal_entity          text        NOT NULL DEFAULT '',
    ADD COLUMN address               text        NOT NULL DEFAULT '',
    ADD COLUMN jurisdiction_country  text        NOT NULL DEFAULT '',
    ADD COLUMN registration_complete boolean     NOT NULL DEFAULT false,
    ADD COLUMN updated_at            timestamptz NOT NULL DEFAULT now();
