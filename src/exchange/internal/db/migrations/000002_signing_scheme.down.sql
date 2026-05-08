ALTER TABLE ramp.tenants DROP CONSTRAINT IF EXISTS tenants_rsa_fields_required;
ALTER TABLE ramp.tenants DROP COLUMN IF EXISTS cloudfront_key_pair_id;
ALTER TABLE ramp.tenants DROP COLUMN IF EXISTS rsa_key_ref;
ALTER TABLE ramp.tenants DROP COLUMN IF EXISTS signing_scheme;
DROP TYPE IF EXISTS ramp.signing_scheme;
