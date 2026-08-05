output "distribution_domain_name" {
  description = "The distribution's CloudFront domain name — the alias target for the route53-dns module's alias_records entry for `hostname`."
  value       = aws_cloudfront_distribution.this.domain_name
}

output "distribution_hosted_zone_id" {
  description = "The CloudFront hosted zone id for alias records (a global constant, exposed here so callers never hardcode it)."
  value       = aws_cloudfront_distribution.this.hosted_zone_id
}

output "distribution_id" {
  description = "The distribution id, for invalidations and console lookups."
  value       = aws_cloudfront_distribution.this.id
}

output "lambda_qualified_arn" {
  description = "The published (versioned) ARN of the edge function — the ARN CloudFront actually runs."
  value       = aws_lambda_function.edge.qualified_arn
}

output "certificate_arn" {
  description = "ARN of the validated ACM certificate the distribution serves."
  value       = aws_acm_certificate_validation.this.certificate_arn
}
