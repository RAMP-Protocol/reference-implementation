# publisher-jwks: test-only HTTP host that serves the catalog-
# contributor's /.well-known/ramp.json (§6.6 schema) so the
# CatalogSignatureMiddleware self-signup flow can resolve the
# contributor's pubkey.
#
# Built for docker-compose.e2e.yml. The entrypoint reads the
# resource-owner's Ed25519 private key from /keys (mounted by compose)
# and renders the §6.6 manifest with the corresponding pubkey + a
# wide-open valid_from/valid_until window into the nginx doc root on
# every cold start.

FROM nginx:1.27-alpine

RUN apk add --no-cache python3 py3-cryptography

COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /usr/local/bin/publisher-jwks-entrypoint.sh
RUN chmod +x /usr/local/bin/publisher-jwks-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/publisher-jwks-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
