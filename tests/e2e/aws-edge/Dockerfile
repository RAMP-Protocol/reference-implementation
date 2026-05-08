# syntax=docker/dockerfile:1.7
# AWS CloudFront canned-policy signed-URL verifier stand-in.
# Node 22 has a built-in fetch + RSA-SHA1 verify via the crypto module,
# so we can stay dependency-free.

FROM node:22-slim
WORKDIR /app
COPY package.json server.mjs ./
ENV NODE_ENV=production \
    PORT=8788
EXPOSE 8788
USER node
ENTRYPOINT ["node", "server.mjs"]
