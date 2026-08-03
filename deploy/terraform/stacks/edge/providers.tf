# Each root stack declares its own provider on purpose: the stacks must stay
# independently applyable (this one is handed to publishers alone), so no
# shared provider config is factored out between them.
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
