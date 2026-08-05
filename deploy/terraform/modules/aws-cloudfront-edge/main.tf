# CloudFront + Lambda@Edge deployment of the RAMP edge worker: the same
# shared edge application the Cloudflare worker runs, on the runtime a
# Route 53-hosted domain gets. The function verifies Ed25519 signed URLs at
# viewer-request and passes authorized requests through, so CloudFront fetches
# the custom origin and content bodies never transit the function.
#
# EVERYTHING in this module must live in us-east-1: Lambda@Edge functions and
# the ACM certificate CloudFront serves are only accepted from there. The
# instantiating stack passes a us-east-1 provider (providers = { aws = ... });
# the precondition on the function turns a wrong-region provider into a
# plan/apply error instead of a confusing AWS rejection.

data "aws_region" "current" {}

# ── TLS certificate (DNS-validated in the Route 53 zone) ─────────────────────

resource "aws_acm_certificate" "this" {
  domain_name       = var.hostname
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# Exactly one validation option exists because the certificate names exactly
# one domain; one() keeps this a single plain resource instead of a for_each
# over a computed set (which cannot be planned before the certificate exists).
locals {
  domain_validation = one(aws_acm_certificate.this.domain_validation_options)
}

resource "aws_route53_record" "validation" {
  zone_id = var.zone_id
  name    = local.domain_validation.resource_record_name
  type    = local.domain_validation.resource_record_type
  ttl     = 60
  records = [local.domain_validation.resource_record_value]
  # Same collision posture as the route53-dns module: a leftover validation
  # record from a previous deployment fails the apply and is retired through
  # whatever manages it, never silently taken over.
  allow_overwrite = false
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [aws_route53_record.validation.fqdn]
}

# ── Lambda@Edge function ─────────────────────────────────────────────────────

# Plain jsonencode (not the aws_iam_policy_document data source) so the
# policy content is known at plan time and the module's test suite can assert
# on it — a mocked data source would return fabricated values.
locals {
  # Both principals are required: lambda.amazonaws.com runs the function,
  # edgelambda.amazonaws.com is what CloudFront's replication service assumes
  # when it copies the function to the edge locations.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"] }
    }]
  })

  # Region wildcard on purpose: Lambda@Edge writes logs in the region that
  # SERVED the request, under a log group whose name carries the deployment
  # region as a prefix (/aws/lambda/us-east-1.<function> in every serving
  # region). A single-region grant silently loses every request served
  # elsewhere. The log-group name stays scoped.
  logs_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/*.${var.name_prefix}-edge:*"
    }]
  })
}

resource "aws_iam_role" "edge" {
  name               = "${var.name_prefix}-edge-role"
  assume_role_policy = local.assume_role_policy
}

resource "aws_iam_role_policy" "edge_logs" {
  name   = "${var.name_prefix}-edge-logs"
  role   = aws_iam_role.edge.id
  policy = local.logs_policy
}

resource "aws_lambda_function" "edge" {
  function_name    = "${var.name_prefix}-edge"
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  handler          = "index.handler"
  runtime          = "nodejs22.x"
  role             = aws_iam_role.edge.arn

  # Viewer-request caps: 128 MB memory, 5 second timeout. The function only
  # verifies and answers small JSON, so the caps are also the right size.
  memory_size = 128
  timeout     = 5

  # CloudFront only associates a PUBLISHED VERSION (the qualified ARN below),
  # never $LATEST.
  publish = true

  lifecycle {
    precondition {
      condition     = data.aws_region.current.name == "us-east-1"
      error_message = "Lambda@Edge functions (and the ACM certificate CloudFront serves) must be created in us-east-1 — instantiate this module with a us-east-1 provider."
    }
  }
}

# ── CloudFront distribution ──────────────────────────────────────────────────

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

# Forwards every viewer header EXCEPT Host (plus all cookies and the full
# query string) to the origin. Host must not be forwarded: the origin serves
# TLS and virtual-hosts for its OWN name, and receiving the distribution's
# hostname instead would route the request wrong.
data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_distribution" "this" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "${var.name_prefix} edge worker"
  aliases         = [var.hostname]
  price_class     = var.price_class
  http_version    = "http2and3"

  origin {
    origin_id   = "${var.name_prefix}-origin"
    domain_name = var.origin_domain

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # ONE behavior on purpose: the shared app serves the well-known routes
  # before its bot gate, so nothing needs a function-bypass behavior, and a
  # single behavior keeps a single code path. Caching is disabled for the
  # demo — correctness first — and the viewer-request placement keeps any
  # later caching decision safe, because the function runs on cache hits too.
  default_cache_behavior {
    target_origin_id       = "${var.name_prefix}-origin"
    viewer_protocol_policy = "redirect-to-https"
    # All methods: unsigned non-read traffic (form posts, webhooks) passes
    # through to the origin by design, so CloudFront must accept it.
    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]
    compress        = true

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id

    # Explicitly empty, never omitted: no trusted key groups exist in this
    # design — Ed25519 verification happens inside the function, and
    # CloudFront's native signed-URL check (RSA-only) stays off. An omitted
    # attribute would read as "leave whatever is there", not as "none".
    trusted_key_groups = []

    lambda_function_association {
      event_type = "viewer-request"
      # The QUALIFIED (versioned) ARN — publish = true above exists for this.
      lambda_arn = aws_lambda_function.edge.qualified_arn
      # The function verifies the URL and headers only; request bodies flow
      # to the origin on pass-through without ever being exposed to it.
      include_body = false
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.this.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
