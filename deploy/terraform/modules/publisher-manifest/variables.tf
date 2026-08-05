variable "exchange_fqdn" {
  description = "Full hostname of the Exchange that represents this publisher, e.g. exchange.demo.publisher.example. The endpoint URL is derived as https://<exchange_fqdn>."
  type        = string
  nullable    = false
}

variable "resource_owner_id" {
  description = "resource_owner_id the publisher manifest attests as settlement payee (carried in the exchange entry's ext object)."
  type        = string
  nullable    = false
}

variable "catalog_contributor_id" {
  description = "Identity authorized to push the publisher's catalog (advertised with the operator relationship)."
  type        = string
  nullable    = false
}
