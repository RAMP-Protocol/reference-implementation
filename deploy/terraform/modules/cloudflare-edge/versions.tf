terraform {
  required_version = ">= 1.8"

  required_providers {
    # Pinned to the 4.x line. This module uses the plural resource names
    # (cloudflare_workers_script / cloudflare_workers_route), which exist
    # un-deprecated in 4.52+ with the same schema as the old singular names —
    # so v4 plans carry no deprecation warnings. v5 additionally reshaped the
    # worker bindings; that migration stays isolated to main.tf.
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.52"
    }
  }
}
