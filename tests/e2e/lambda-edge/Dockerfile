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

# The full node image rather than -slim: @ramp-protocol/sdk-l1 is a git
# dependency (git+https://…/protocol#<sha>) that npm ci clones, and this image
# ships git already. The slim base would need an apt install for it, which is
# one more thing that can fail in a build that only needs a bundler.
FROM node:22 AS builder
WORKDIR /app
COPY src/edge/package.json src/edge/package-lock.json ./
RUN npm ci --include=dev
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
