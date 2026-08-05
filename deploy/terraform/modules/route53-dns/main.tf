# Service records for a RAMP deployment whose DNS lives in Route 53: plain A
# records for the VM-hosted service hostnames (the same record set the
# cloudflare-dns module creates on Cloudflare-fronted deployments) plus alias
# records for hostnames served by CloudFront.
#
# allow_overwrite is pinned to false explicitly (not left to the provider
# default) on purpose: if a name already exists in the zone — for example a
# record a previous deployment still owns — the apply fails instead of
# silently taking the record over. Retire the old record through whatever
# manages it, then apply. This also keeps destroy honest: only records this
# module created are ever removed.

resource "aws_route53_record" "a" {
  for_each = var.a_records

  zone_id         = var.zone_id
  name            = each.key
  type            = "A"
  ttl             = var.ttl
  records         = [each.value]
  allow_overwrite = false
}

resource "aws_route53_record" "alias_a" {
  for_each = var.alias_records

  zone_id         = var.zone_id
  name            = each.key
  type            = "A"
  allow_overwrite = false

  alias {
    name                   = each.value.target_domain
    zone_id                = each.value.target_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "alias_aaaa" {
  for_each = var.alias_records

  zone_id         = var.zone_id
  name            = each.key
  type            = "AAAA"
  allow_overwrite = false

  alias {
    name                   = each.value.target_domain
    zone_id                = each.value.target_zone_id
    evaluate_target_health = false
  }
}
