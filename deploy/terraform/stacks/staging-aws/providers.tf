provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = var.name_prefix
      ManagedBy = "deploy/terraform/stacks/staging-aws"
    }
  }
}

# Each root stack declares its own provider on purpose: the stacks must stay
# independently applyable (stacks/edge is handed to publishers alone), so no
# shared provider config is factored out between them.
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
