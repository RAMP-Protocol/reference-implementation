# publisher-jwks: test-only HTTP host that serves the catalog-
# contributor's /.well-known/ramp.json (§6.6 schema) so the
# CatalogSignatureMiddleware self-signup flow can resolve the
# contributor's pubkey.
#
# Built for docker-compose.e2e.yml with the REPO ROOT as build context
# (context: ., dockerfile: deploy/publisher-jwks/Dockerfile) so the shared
# key helpers in scripts/lib travel into the image. The entrypoint reads the
# resource-owner's Ed25519 private key from /keys (mounted by compose)
# and renders the §6.6 manifest with the corresponding pubkey + a
# wide-open valid_from/valid_until window into the nginx doc root on
# every cold start.

FROM nginx:1.27-alpine

RUN apk add --no-cache python3 py3-cryptography

COPY deploy/publisher-jwks/nginx.conf /etc/nginx/nginx.conf
COPY deploy/publisher-jwks/entrypoint.sh /usr/local/bin/publisher-jwks-entrypoint.sh
# The one WBA entry shape + validity-window helper, shared with every key-gen
# script; the entrypoint imports it instead of carrying a shell-side copy.
COPY scripts/lib/ed25519_keys.py /opt/ramp/lib/ed25519_keys.py
RUN chmod +x /usr/local/bin/publisher-jwks-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/publisher-jwks-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
