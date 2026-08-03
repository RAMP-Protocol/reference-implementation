variable "name_prefix" {
  description = "Prefix for every resource name/tag this module creates (e.g. \"ramp-staging\")."
  type        = string
  nullable    = false
}

variable "instance_type" {
  description = "EC2 instance type. Must be amd64 — the Exchange image is CGO/amd64-only, no multi-arch image is published."
  type        = string
  default     = "t3.large"
  nullable    = false

  validation {
    # Reject arm64 families (Graviton + Apple silicon): the stack's images are
    # amd64-only and an arm64 instance would pull-fail or crash at exec format.
    # Character classes cover the size/variant suffixes (c7g, c7gd, c7gn, ...);
    # amd64 near-misses like g5 (vs g5g) and i4i (vs i4g) must keep passing.
    condition     = !can(regex("^(a1|t4g|c[678]g|m[678]g|r[678]g|x[28]g|g5g|im4gn|is4gen|i[48]g|hpc7g|mac2)", var.instance_type))
    error_message = "arm64 instance types are not supported: the RAMP images are amd64-only."
  }
}

variable "ssh_public_key" {
  description = "OpenSSH public key installed for the default OS user (ubuntu)."
  type        = string
  nullable    = false
}

variable "ssh_ingress_cidr" {
  description = "CIDR allowed to reach SSH (port 22). Use your own address as a /32 — never 0.0.0.0/0."
  type        = string
  nullable    = false

  validation {
    # A valid IPv4 CIDR with a prefix of at least /8. The old check compared
    # against the literal "0.0.0.0/0", which let equally-open ranges through
    # ("0.0.0.0/1", "1.2.3.4/0"). The ternary keeps the prefix arithmetic from
    # erroring on malformed input: cidrnetmask() succeeding guarantees an
    # IPv4 address, a slash, and a numeric prefix.
    condition = (
      can(cidrnetmask(var.ssh_ingress_cidr))
      ? tonumber(split("/", var.ssh_ingress_cidr)[1]) >= 8
      : false
    )
    error_message = "SSH ingress must be a valid IPv4 CIDR no wider than /8 — use your own address (e.g. 203.0.113.7/32), never an open range like 0.0.0.0/0."
  }
}

variable "user_data" {
  description = "cloud-init user data (rendered by the compose-stack module). Gzipped by this module to stay under EC2's 16 KB raw limit. Contains key material — treat state as secret."
  type        = string
  sensitive   = true
  nullable    = false
}

variable "root_volume_gb" {
  description = "Root EBS volume size in GiB (gp3). Holds Docker images plus Postgres/Redis/TigerBeetle data volumes."
  type        = number
  default     = 40
  nullable    = false
}

variable "vpc_cidr" {
  description = "CIDR of the minimal VPC this module creates (one public subnet spanning it)."
  type        = string
  default     = "10.80.0.0/24"
  nullable    = false
}

variable "user_data_replace_on_change" {
  description = "Recreate the instance when user data changes. True keeps the VM's config exactly what Terraform rendered (staging posture: data is disposable); set false to keep the instance and apply config changes by hand."
  type        = bool
  default     = true
  nullable    = false
}
