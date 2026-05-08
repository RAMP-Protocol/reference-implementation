-- Adds the tenant-level signing scheme selector introduced for the
-- asymmetric-signed-URL plan (CLAUDE.md: no HMAC, Ed25519 for
-- Cloudflare/Fastly, RSA CloudFront for AWS-fronted publishers).

CREATE TYPE ramp.signing_scheme AS ENUM (
    'ED25519',
    'AWS_CLOUDFRONT_RSA'
);

ALTER TABLE ramp.tenants
    ADD COLUMN signing_scheme         ramp.signing_scheme NOT NULL DEFAULT 'ED25519',
    ADD COLUMN rsa_key_ref            TEXT,
    ADD COLUMN cloudfront_key_pair_id TEXT;

-- RSA scheme requires both the private-key pointer and the CloudFront key-pair
-- ID. Ed25519 tenants leave both nullable. Enforced in SQL so bad writes cannot
-- slip past the repo layer.
ALTER TABLE ramp.tenants
    ADD CONSTRAINT tenants_rsa_fields_required
    CHECK (
        signing_scheme <> 'AWS_CLOUDFRONT_RSA'
        OR (rsa_key_ref IS NOT NULL AND cloudfront_key_pair_id IS NOT NULL)
    );
