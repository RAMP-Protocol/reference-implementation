terraform {
  required_version = ">= 1.8"

  # Provider-neutral module: it renders templates and mints a database
  # password, nothing else. Cloud resources live in sibling modules (aws-vm),
  # so a future Hetzner/GCP layer reuses this module unchanged.
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
