-- name: Revoke :one
-- Append thumbprint to the subdomain's revoked set and advance as_of to a value
-- strictly greater than both its previous value and now_epoch, so every published
-- snapshot carries a strictly-increasing as_of even if two revokes land in the same
-- clock tick or the clock steps backward. A thumbprint already present is not
-- duplicated, but the publication still bumps as_of.
INSERT INTO identity.key_revocation (subdomain, as_of, revoked)
VALUES (sqlc.arg(subdomain), sqlc.arg(now_epoch), ARRAY[sqlc.arg(thumbprint)::text])
ON CONFLICT (subdomain) DO UPDATE SET
    as_of = GREATEST(identity.key_revocation.as_of + 1, sqlc.arg(now_epoch)),
    revoked = CASE
        WHEN sqlc.arg(thumbprint) = ANY (identity.key_revocation.revoked)
            THEN identity.key_revocation.revoked
        ELSE array_append(identity.key_revocation.revoked, sqlc.arg(thumbprint))
    END
RETURNING as_of;

-- name: GetRevocation :one
SELECT as_of, revoked
FROM identity.key_revocation
WHERE subdomain = sqlc.arg(subdomain);
