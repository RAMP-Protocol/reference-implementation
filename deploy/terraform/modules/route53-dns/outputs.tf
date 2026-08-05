output "record_hostnames" {
  description = "Map of record name to the full domain name Route 53 created (e.g. \"exchange.demo\" => exchange.demo.publisher.example), covering both the plain A records and the alias records."
  value = merge(
    { for name, record in aws_route53_record.a : name => record.fqdn },
    { for name, record in aws_route53_record.alias_a : name => record.fqdn },
  )
}
