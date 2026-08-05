variable "zone_id" {
  description = "Id of the EXISTING Route 53 hosted zone the records are created in. The zone itself is never created, imported, or destroyed by this module — it may be shared with other projects, and this module must only ever touch its own records."
  type        = string
  nullable    = false
}

variable "a_records" {
  description = "Map of record name (relative to the zone, e.g. \"exchange.demo\" or \"*.mcp.demo\") to IPv4 address."
  type        = map(string)
  nullable    = false
  # No non-empty validation on purpose: an empty map is a valid no-op plan
  # (zero records), not a misconfiguration — same contract as the
  # cloudflare-dns module this mirrors.
}

variable "alias_records" {
  description = "Map of record name (relative to the zone) to an AWS alias target — e.g. a CloudFront distribution's domain name and its hosted zone id. Each entry creates an A and an AAAA alias so IPv6 viewers resolve too."
  type = map(object({
    target_domain  = string
    target_zone_id = string
  }))
  default  = {}
  nullable = false
}

variable "ttl" {
  description = "TTL in seconds for the plain A records (alias records take the target's TTL and have none of their own)."
  type        = number
  default     = 300
  nullable    = false
}
