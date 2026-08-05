variable "name_prefix" {
  description = "Prefix every named resource carries (function, IAM role, policy). One prefix, derived everywhere, so an ARN-scoped IAM policy for the deployer can enumerate this deployment's resources instead of holding wildcard grants."
  type        = string
  default     = "ramp"
  nullable    = false
}

variable "lambda_zip_path" {
  description = "Path to the pre-built Lambda@Edge bundle zip (src/edge/dist/lambda-edge.zip). Build it with deploy/terraform/scripts/build-lambda-edge.sh before apply — this module never builds it, and the per-deployment config is baked inside the zip (Lambda@Edge has no environment variables)."
  type        = string
  nullable    = false

  # Fail at plan with a clear message instead of at apply inside
  # filebase64sha256(): the bundle is a build artifact, so a fresh checkout
  # legitimately lacks it and should be told what to run.
  validation {
    condition     = fileexists(var.lambda_zip_path)
    error_message = "lambda_zip_path points at a file that does not exist — run deploy/terraform/scripts/build-lambda-edge.sh <config.json> first."
  }
}

variable "hostname" {
  description = "Publisher hostname the distribution serves (certificate domain and CloudFront alias), e.g. demo.publisher.example. DNS for it is NOT created here — point it at the distribution with the route53-dns module's alias_records, using this module's distribution outputs."
  type        = string
  nullable    = false
}

variable "zone_id" {
  description = "Route 53 hosted zone id the certificate's DNS-validation record is created in. Must be the zone that serves `hostname`."
  type        = string
  nullable    = false
}

variable "origin_domain" {
  description = "Hostname of the custom origin CloudFront fetches verified content from (the VM's publisher origin, e.g. origin.demo.publisher.example). It must serve TLS for its own name — CloudFront connects with SNI for this value, not for `hostname`."
  type        = string
  nullable    = false
}

variable "price_class" {
  description = "CloudFront price class. The cheapest tier serves North America and Europe only, which is enough for a demo."
  type        = string
  default     = "PriceClass_100"
  nullable    = false
}
