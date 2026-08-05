# Unit tests for the aws-cloudfront-edge module. The AWS provider is MOCKED:
# no credentials, no API calls, no real resources. The bundle input is a
# placeholder fixture — the module only fingerprints the file.
#
# Run from the module directory: terraform init && terraform test

mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      name = "us-east-1"
    }
  }
}

variables {
  name_prefix     = "demo"
  lambda_zip_path = "./tests/fixtures/lambda-edge-placeholder.zip"
  hostname        = "demo.publisher.example"
  zone_id         = "Z0000000EXAMPLE"
  origin_domain   = "origin.demo.publisher.example"
}

run "lambda_matches_viewer_request_caps_and_is_published" {
  command = plan

  assert {
    condition     = aws_lambda_function.edge.memory_size == 128 && aws_lambda_function.edge.timeout == 5
    error_message = "Viewer-request functions are capped at 128 MB / 5 s — the module must stay inside the caps"
  }

  assert {
    condition     = aws_lambda_function.edge.publish == true
    error_message = "CloudFront only associates a published version, so publish must be true"
  }

  assert {
    condition     = aws_lambda_function.edge.runtime == "nodejs22.x" && aws_lambda_function.edge.handler == "index.handler"
    error_message = "The bundle is built for nodejs22.x with a flat index.mjs exporting `handler`"
  }
}

run "role_trusts_both_lambda_principals" {
  command = plan

  # Without edgelambda.amazonaws.com in the trust policy, CloudFront cannot
  # replicate the function to edge locations and the association fails.
  assert {
    condition = alltrue([
      for principal in ["lambda.amazonaws.com", "edgelambda.amazonaws.com"] :
      contains(jsondecode(aws_iam_role.edge.assume_role_policy).Statement[0].Principal.Service, principal)
    ])
    error_message = "The execution role must trust both lambda.amazonaws.com and edgelambda.amazonaws.com"
  }
}

run "log_permissions_span_every_serving_region" {
  command = plan

  # Lambda@Edge writes logs in the region that served the request; a
  # single-region grant silently loses every request served elsewhere.
  assert {
    condition     = startswith(jsondecode(aws_iam_role_policy.edge_logs.policy).Statement[0].Resource, "arn:aws:logs:*:")
    error_message = "The logs grant must span all regions (arn:aws:logs:*), name-scoped to the function's log groups"
  }

  assert {
    condition     = strcontains(jsondecode(aws_iam_role_policy.edge_logs.policy).Statement[0].Resource, "/aws/lambda/*.demo-edge")
    error_message = "The logs grant must stay scoped to this function's region-prefixed log-group names"
  }
}

run "distribution_gates_every_request_at_viewer_request" {
  command = plan

  assert {
    condition = alltrue([
      for assoc in aws_cloudfront_distribution.this.default_cache_behavior[0].lambda_function_association :
      assoc.event_type == "viewer-request" && assoc.include_body == false
    ]) && length(aws_cloudfront_distribution.this.default_cache_behavior[0].lambda_function_association) == 1
    error_message = "Exactly one association, at viewer-request (runs on cache hits too), without body exposure"
  }

  # No /.well-known/* bypass behavior: the shared app serves well-known routes
  # before its bot gate, so a second behavior would only add a second code
  # path. One behavior total means ordered_cache_behavior stays empty.
  assert {
    condition     = length(aws_cloudfront_distribution.this.ordered_cache_behavior) == 0
    error_message = "One default behavior only — the well-known bypass from the previous deployment must not come back"
  }

  # Explicitly none, never omitted: Ed25519 verification lives in the
  # function; CloudFront's RSA-only native check stays off.
  assert {
    condition     = length(aws_cloudfront_distribution.this.default_cache_behavior[0].trusted_key_groups) == 0
    error_message = "trusted_key_groups must be explicitly empty"
  }
}

run "distribution_serves_the_publisher_hostname_over_tls" {
  command = plan

  assert {
    condition     = contains(aws_cloudfront_distribution.this.aliases, "demo.publisher.example")
    error_message = "The distribution must serve the publisher hostname as an alias"
  }

  assert {
    condition = alltrue([
      for origin in aws_cloudfront_distribution.this.origin :
      one(origin.custom_origin_config[*].origin_protocol_policy) == "https-only"
    ])
    error_message = "The origin fetch must be HTTPS-only — the VM origin serves TLS via its own certificate"
  }

  assert {
    condition     = one(aws_cloudfront_distribution.this.viewer_certificate[*].ssl_support_method) == "sni-only"
    error_message = "SNI-only keeps the distribution off the dedicated-IP surcharge"
  }
}

run "certificate_validates_via_dns_without_overwriting_records" {
  command = plan

  assert {
    condition     = aws_acm_certificate.this.domain_name == "demo.publisher.example" && aws_acm_certificate.this.validation_method == "DNS"
    error_message = "The certificate must name the served hostname and validate via DNS"
  }

  assert {
    condition     = aws_route53_record.validation.allow_overwrite == false
    error_message = "A leftover validation record from a previous deployment must fail the apply, never be overwritten"
  }
}

run "behavior_uses_the_two_managed_policies_and_accepts_all_methods" {
  command = plan

  # Swap either id for a hand-rolled policy and this fails: caching stays
  # disabled and the viewer's Host header stays off the origin fetch.
  assert {
    condition     = aws_cloudfront_distribution.this.default_cache_behavior[0].cache_policy_id == data.aws_cloudfront_cache_policy.caching_disabled.id
    error_message = "The default behavior must use the managed CachingDisabled policy"
  }

  assert {
    condition     = aws_cloudfront_distribution.this.default_cache_behavior[0].origin_request_policy_id == data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    error_message = "The default behavior must use the managed AllViewerExceptHostHeader policy"
  }

  # Unsigned non-read traffic (form posts, webhooks) passes through to the
  # origin by design, so CloudFront must accept every method.
  assert {
    condition = alltrue([
      for method in ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"] :
      contains(aws_cloudfront_distribution.this.default_cache_behavior[0].allowed_methods, method)
    ])
    error_message = "All seven methods must be allowed — non-read pass-through traffic would otherwise be rejected before the function runs"
  }
}

run "missing_bundle_fails_the_plan_with_a_pointer_to_the_build_script" {
  command = plan

  variables {
    lambda_zip_path = "./tests/fixtures/does-not-exist.zip"
  }

  expect_failures = [var.lambda_zip_path]
}

run "wrong_region_provider_fails_the_plan" {
  command = plan

  # Lambda@Edge and CloudFront's ACM certificate are only accepted from
  # us-east-1 — a wrong-region provider must fail loudly at plan, not as a
  # confusing AWS API rejection at apply.
  override_data {
    target = data.aws_region.current
    values = {
      name = "eu-west-1"
    }
  }

  expect_failures = [aws_lambda_function.edge]
}
