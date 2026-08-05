# Unit tests for the route53-dns module. The AWS provider is MOCKED: no
# credentials, no API calls, no real records.
#
# Run from the module directory: terraform init && terraform test

mock_provider "aws" {}

# Mirrors what a demo deployment actually passes — the VM service hostnames
# under a delegated sub-label, the agent-directory wildcard, and the edge
# hostname as a CloudFront alias — so the assertions cover the shapes the real
# caller uses rather than a reduced fixture.
variables {
  zone_id = "Z0000000EXAMPLE"
  a_records = {
    "exchange.demo" = "198.51.100.10"
    "broker.demo"   = "198.51.100.10"
    "mcp.demo"      = "198.51.100.10"
    "login.demo"    = "198.51.100.10"
    "origin.demo"   = "198.51.100.10"
    "*.mcp.demo"    = "198.51.100.10"
  }
  alias_records = {
    "demo" = {
      target_domain = "d111111abcdef8.cloudfront.net"
      # CloudFront's fixed hosted zone id, the same for every distribution.
      target_zone_id = "Z2FDTNDATAQYW2"
    }
  }
}

run "one_a_record_per_service" {
  command = plan

  assert {
    condition     = length(aws_route53_record.a) == 6
    error_message = "Exactly one A record per map entry"
  }

  assert {
    condition = alltrue([
      for record in aws_route53_record.a :
      record.type == "A" && length(record.records) == 1 && contains(record.records, "198.51.100.10") && record.ttl == 300
    ])
    error_message = "Every plain record must be an A record pointing at the given address with the configured TTL"
  }
}

run "wildcard_label_survives_verbatim" {
  command = plan

  # The map key is the record name. Nothing may normalise or escape it: the
  # agent Web Bot Auth directories live at <agent>.mcp.<sub>.<zone>, hostnames
  # that do not exist until a developer signs up, so a wildcard is the only
  # record Terraform can create for them ahead of time.
  assert {
    condition     = aws_route53_record.a["*.mcp.demo"].name == "*.mcp.demo"
    error_message = "The wildcard label must reach Route 53 unchanged — a sanitised name would silently cover nothing"
  }
}

run "alias_entries_create_a_and_aaaa_pairs" {
  command = plan

  assert {
    condition     = length(aws_route53_record.alias_a) == 1 && length(aws_route53_record.alias_aaaa) == 1
    error_message = "Every alias entry must create exactly one A and one AAAA record"
  }

  assert {
    condition = alltrue([
      for record in merge(aws_route53_record.alias_a, aws_route53_record.alias_aaaa) :
      one(record.alias[*].name) == "d111111abcdef8.cloudfront.net" &&
      one(record.alias[*].zone_id) == "Z2FDTNDATAQYW2" &&
      one(record.alias[*].evaluate_target_health) == false
    ])
    error_message = "Alias records must target the given distribution without health evaluation"
  }
}

run "empty_maps_plan_to_zero_records" {
  command = plan

  # Pins the contract variables.tf documents: an empty map is a valid no-op
  # plan (zero records), not a misconfiguration.
  variables {
    a_records     = {}
    alias_records = {}
  }

  assert {
    condition     = length(aws_route53_record.a) == 0 && length(aws_route53_record.alias_a) == 0 && length(aws_route53_record.alias_aaaa) == 0
    error_message = "Empty input maps must plan zero records"
  }
}

run "existing_records_are_never_overwritten" {
  command = plan

  # The hosted zone is shared with other projects and may still hold a name a
  # previous deployment owns. Overwrite must stay off so the apply FAILS on a
  # collision instead of silently taking the record over.
  assert {
    condition = alltrue([
      for record in merge(aws_route53_record.a, aws_route53_record.alias_a, aws_route53_record.alias_aaaa) :
      record.allow_overwrite == false
    ])
    error_message = "allow_overwrite must remain false on every record so a name collision fails the apply"
  }
}
