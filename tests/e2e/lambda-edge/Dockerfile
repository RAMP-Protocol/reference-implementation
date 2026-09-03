# Lambda@Edge runtime for the E2E stack: the REAL production artifact running
# inside the AWS Lambda runtime image.
#
# The bundle is produced by src/edge/scripts/build-lambda-edge.mjs — the same
# script a deployment runs — so what the tests drive is the artifact that would
# be uploaded to Lambda, per-deployment config baked in and all, not a lookalike
# re-assembled for the test. The AWS base image ships the Lambda Runtime
# Interface Emulator, so the container answers real Lambda invocations at
# POST /2015-03-31/functions/function/invocations on port 8080.
#
# Two bundles are built from two configs (see write-configs.mjs): index.mjs
# publishes a Web Bot Auth key, no-wba.mjs publishes none. One container serves
# one handler, so the compose stack runs two services off this one image and
# each covers one posture of the WBA directory route.
#
# Build context is the repo root (see docker-compose.e2e.yml) so both src/edge/
# and this directory are reachable.

# @ramp-protocol/sdk-l1 is pinned by full commit SHA on GitHub
# (git+https://…/protocol#<sha>), resolved off-commit like the Go and Python pins,
# so no sibling checkout is mirrored in and any shallow workdir works.
#
# npm does NOT clone it: for a GitHub-hosted spec pinned to a SHA it fetches a
# codeload tarball over plain HTTPS, and a clone is pacote's fallback when that
# fetch fails. Written out once, with the evidence, in
# src/edge/Dockerfile.miniflare — three copies of it is how the correction
# reached three sites of eight last time.
#
# The full node image rather than -slim so git is present for that fallback
# without an apt install — one less thing to fail in a build that only needs a
# bundler. The slim base would work on the normal path either way.
FROM node:22 AS builder
WORKDIR /app
COPY src/edge/package.json src/edge/package-lock.json ./
# Persist npm's download cache across builds — the slowest two stages of a cold
# stack build. The codeload response above lands in it with every registry
# tarball this step downloads. The mount lives with the builder, so nothing here
# reaches a layer.
#
# id, because BuildKit otherwise names a cache mount after its target and all
# three npm mounts in this stack would be one cache under one lock, serializing
# images compose builds concurrently. Per image, one writer each.
RUN --mount=type=cache,id=npm-lambda-edge,target=/root/.npm,sharing=locked \
    npm ci --include=dev
COPY src/edge/ ./
COPY tests/e2e/lambda-edge/write-configs.mjs /build/write-configs.mjs
RUN node /build/write-configs.mjs --out-dir /build/config
# The build script smoke-invokes each bundle it produces (manifest route plus an
# unsigned human read), which needs no network — so a broken bake fails the
# image build here rather than the first test.
RUN node scripts/build-lambda-edge.mjs --config /build/config/with-wba.json \
      --out-dir dist/lambda-edge-with-wba \
    && node scripts/build-lambda-edge.mjs --config /build/config/no-wba.json \
      --out-dir dist/lambda-edge-no-wba

FROM public.ecr.aws/lambda/nodejs:22
COPY --from=builder /app/dist/lambda-edge-with-wba/index.mjs ${LAMBDA_TASK_ROOT}/index.mjs
COPY --from=builder /app/dist/lambda-edge-no-wba/index.mjs ${LAMBDA_TASK_ROOT}/no-wba.mjs
# Kept out of the task root so the deployed surface stays exactly the two
# bundles above.
COPY tests/e2e/lambda-edge/healthcheck.mjs /opt/healthcheck.mjs
CMD ["index.handler"]
