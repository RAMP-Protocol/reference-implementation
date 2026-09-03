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

variable "ssh_operators" {
  description = "Operators allowed to SSH in, keyed by name. Each key is installed with an OpenSSH from= restriction limiting it to that operator's own addresses; the security group opens the union. WARNING: editing this map replaces the VM and destroys its data — see the deployment guide."
  type = map(object({
    public_key   = string
    source_cidrs = set(string)
  }))
  nullable = false

  validation {
    condition     = length(var.ssh_operators) > 0
    error_message = "ssh_operators must name at least one operator: an empty map leaves the instance with no way in, and this stack has no break-glass path."
  }

  validation {
    condition     = alltrue([for o in var.ssh_operators : length(o.source_cidrs) > 0])
    error_message = "Every operator needs at least one entry in source_cidrs: an operator with no address has a key that no address may present."
  }

  validation {
    # /32 only. Anything wider lets an operator write 203.0.113.7/24 with host
    # bits set: AWS canonicalizes the security-group rule to 203.0.113.0/24 and
    # returns that while the configuration still says 203.0.113.7/24, which is a
    # permanent plan diff on every apply. from= keeps the original string, so
    # the two halves of the design would also stop matching. The ternary keeps
    # the prefix arithmetic from erroring on malformed input: cidrnetmask()
    # succeeding guarantees an IPv4 address, a slash, and a numeric prefix.
    condition = alltrue([
      for o in var.ssh_operators : alltrue([
        for c in o.source_cidrs :
        can(cidrnetmask(c)) ? tonumber(split("/", c)[1]) == 32 : false
      ])
    ])
    error_message = "Every source_cidrs entry must be a single IPv4 host address written as /32 (e.g. 203.0.113.7/32). Wider prefixes are refused: AWS rewrites them and the security group then disagrees with the from= restriction forever."
  }

  validation {
    # Compares the key TYPE and BLOB only. OpenSSH matches on those and ignores
    # the trailing comment, so "ssh-ed25519 AAAA... alice" and
    # "ssh-ed25519 AAAA... bob" are the same credential presented twice. That
    # matters because when a line's key matches but its from= refuses the
    # connecting address, OpenSSH logs the refusal and keeps reading the file
    # for another matching line — so one blob under two operators is accepted
    # from the union of both address sets, which is exactly the binding this
    # design exists to enforce. try() keeps a malformed key from erroring here;
    # the shape check below is what reports that.
    condition = length(distinct([
      for o in var.ssh_operators :
      try(join(" ", slice(compact(split(" ", trimspace(o.public_key))), 0, 2)),
      trimspace(o.public_key))
    ])) == length(var.ssh_operators)
    error_message = "Two operators list the same public key. One key under two names is accepted from the union of both address sets, which removes the per-operator binding entirely — give each operator their own key."
  }

  validation {
    # SHAPE only: one line, a known key type, a base64 blob with padding at the
    # end if at all, and an optional trailing comment. The anchoring is what
    # matters. A key containing a newline would inject a second authorized_keys
    # line carrying no from=, which is silent unrestricted access; a key that
    # already carries its own options would land behind ours. This does NOT
    # prove the blob decodes to a usable key, and no Terraform expression can —
    # only a real SSH login does. The two sk-* FIDO2 types are accepted on
    # purpose: a hardware-backed key is what a security-conscious operator
    # brings, and refusing it would push them onto a weaker credential.
    # Certificate types (*-cert-v01@openssh.com) stay refused, because a
    # certificate carries its own principals and validity — a second
    # authorization mechanism this design does not model. The literal dot in
    # "@openssh\\.com" needs the doubled backslash: \. is not a valid HCL
    # string escape.
    condition = alltrue([
      for o in var.ssh_operators :
      can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\\.com|sk-ecdsa-sha2-nistp256@openssh\\.com) [A-Za-z0-9+/]+={0,2}( [^\n]*)?$",
      trimspace(o.public_key)))
    ])
    error_message = "public_key must be the one-line CONTENTS of the operator's .pub file (\"ssh-ed25519 AAAA... name@host\"), not a path to it — Terraform variable files cannot call file(), so paste the output of `cat ~/.ssh/id_ed25519.pub`. Accepted types: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256/384/521, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com. No newlines and no leading options: either would install a second, unrestricted line."
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
