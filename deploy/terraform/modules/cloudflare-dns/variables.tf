variable "zone_id" {
  description = "Cloudflare zone id the records are created on."
  type        = string
  nullable    = false
}

variable "a_records" {
  description = "Map of record name (relative to the zone, e.g. \"exchange\") to IPv4 address."
  type        = map(string)
  nullable    = false
  # No non-empty validation on purpose: an empty map is a valid no-op plan
  # (zero records), not a misconfiguration — unlike a worker without routes,
  # nothing silently misbehaves.
}

variable "proxied" {
  description = "Whether the records go through Cloudflare's proxy. False (DNS-only) is the right setting for service hostnames terminated by Caddy on the VM: ACME HTTP-01 reaches the real origin and agents talk to the services directly."
  type        = bool
  default     = false
  nullable    = false
}

variable "ttl" {
  description = "Record TTL in seconds (ignored by Cloudflare when proxied)."
  type        = number
  default     = 300
  nullable    = false
}

variable "comment" {
  description = "Comment stamped on every record."
  type        = string
  default     = "Managed by RAMP deploy/terraform"
  nullable    = false
}
