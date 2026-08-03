# A records for the RAMP service hostnames. DNS-only by default (proxied =
# false): TLS is terminated by Caddy on the VM, ACME HTTP-01 must reach it,
# and the edge worker's ORIGIN_URL fetch must land on the real origin.

resource "cloudflare_record" "this" {
  for_each = var.a_records

  zone_id = var.zone_id
  name    = each.key
  type    = "A"
  content = each.value
  proxied = var.proxied
  ttl     = var.proxied ? 1 : var.ttl
  comment = var.comment
}
