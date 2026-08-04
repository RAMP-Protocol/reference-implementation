# ADR-024 — Container Image Distribution

**Status:** Accepted (2026-08-03)
**Relates to:** ADR-020 (RAMP SDK layered libraries) — the same question asked about library packages rather than container images.

---

## Context

Three services of this implementation ship as containers: the Exchange, the Broker
and the Identity service. Each has a Dockerfile under `src/<service>/` and a
deployment document that tells an operator how to run it.

Until this decision, nothing was published anywhere. Two of those three deployment
documents nonetheless stated that the image was available from a public registry,
and named one we do not use. The image names they printed were unqualified, so a
reader who copied them resolved a registry we have never pushed to and got "not
found". The documents promised an artifact that did not exist, in a place it would
never have been.

Two things are deliberately outside this decision:

- **The Edge worker.** It deploys as a Cloudflare Worker, not a container. Its
  Dockerfile is a local test harness for the e2e stack and is not a deliverable.
- **Postgres, Redis, TigerBeetle, Vault and the identity provider.** These are
  upstream images pulled from their own publishers, pinned by us, built by them.

Two other push paths for these same three images already exist, and neither is what
this decision governs. `scripts/ecr-push.sh` pushes to a private AWS registry to roll
the demo deployment. `deploy/terraform/scripts/build-push-images.sh` pushes to
whichever registry a staging stack is configured with. Both are deployment plumbing:
one environment, one audience, a registry chosen per deployment. This decision is
about the public artifacts of a reference implementation, where the audience is
anyone and the guarantees have to hold without us being in the room. All three
coexist and none shares a naming scheme with the others.

## Decision

### D1 — Images are published to the GitHub Container Registry, under flat names

`ghcr.io/ramp-protocol/exchange`, `ghcr.io/ramp-protocol/broker`,
`ghcr.io/ramp-protocol/identity`. Not nested under the repository name.

The source already lives on GitHub, so the registry is part of the same account and
the build needs no credential that anyone has to hold, store or rotate (see D4).
Names are flat because the service is the unit an operator deploys; which repository
it was built from is recorded in the image's `org.opencontainers.image.source` label
instead. That label carries weight: it is what links the published package to its
repository, and linking is what makes the package manageable and publishable at
all.

Registry names must be lower case, so the organisation appears as `ramp-protocol`.

### D2 — One immutable version tag per build, and no `latest`

Each build publishes exactly one tag: the version, with no leading `v`. No `latest`,
and no moving major or minor pointer such as `1.0`. A published tag names one build
and is never repointed.

A `latest` may be introduced later, once there is a release history for it to point
at. Nothing in this decision prevents that.

The immediate consequence is intended: `docker pull ghcr.io/ramp-protocol/exchange`
with no tag **fails**. An operator who omits the version finds out immediately,
rather than silently running whatever was pushed most recently.

Production should deploy the digest, not the tag. Every image has a `@sha256:...`
address whether or not it is tagged. Our tags are written once and never moved, but
that is a policy of ours; a digest is content-addressed and cannot be moved by
anyone. Where the two disagree, the digest is the one that is a guarantee.

### D3 — `linux/amd64` only

No arm64 variant, and no multi-architecture manifest. The provenance attestation
that the build tooling would otherwise attach is switched off for the same reason:
it turns the published tag into an image index, which is a multi-platform manifest
in all but name, and only one platform is published.

What an ARM build would cost, for whoever revisits this. The Broker and the Identity
service are pure Go with cgo disabled, and would need no more than the extra platform
in the build. The Exchange is different: it links a C library for the TigerBeetle
ledger client, and cgo cannot cross-compile without a cross toolchain, so an x86
runner cannot produce its arm64 variant at all. The clean route is a native arm64
runner plus a manifest merge. That is real work, and no target deployment needs it
today.

### D4 — The build runs in the public repository, authenticated by its per-run token

`.github/workflows/publish-images.yml` builds all three images and pushes them,
signing in to the registry with the token GitHub issues for the run. No personal
access token is created, stored, or rotated for this purpose, and the workflow
contains nothing secret.

The workflow is authored **here**, in the source repository, and travels to the
public repository through the publish allowlist in `scripts/published-paths.sh`. It
cannot be authored on the public repository instead: the publish rebuilds that tree
from the allowlist and deletes everything it does not reproduce, so a workflow
created there would survive exactly until the next snapshot.

### D5 — Publishing the source and publishing the images are separate acts

A snapshot of the source builds nothing. The workflow listens for version tags only,
and the publish pushes a branch. Pushing a version tag to the public repository is
what produces images.

The separation is the point. Documentation-only snapshots are frequent, and each one
would otherwise reissue three images with a new build date and a new digest for
unchanged code. Deciding to publish source and deciding to publish binaries are
different decisions and should stay two commands.

## Consequences

**Positive.**

- An operator pulls an artifact instead of compiling one, and needs no Go toolchain,
  no C toolchain, and no copy of the source to run the platform.
- Nothing to leak. There is no long-lived registry credential anywhere, so there is
  none to rotate and none to lose.
- The absence of `latest` removes a whole class of "which version is production
  actually running" incidents, at the cost of making every example more verbose.
- Every image is traceable back to the commit it was built from through the
  `revision` and `version` labels the workflow stamps at build time.

**Negative.**

- Anyone on an ARM machine runs these under emulation. That is fine for inspection
  and wrong for measurement, and every deployment document has to say so.
- The allowlist entry that carries the workflow copies the whole `.github` subtree.
  Anything added there later reaches the public repository with no further decision.
  The allowlist file records this; per-file granularity would have to be built if it
  ever matters.
- Publishing stays ours. Whoever develops the protocol publishes the images, so a
  third party who wants a different registry has to build their own.

## Non-goals

- **Signing and attestation.** Images are not signed, and no SBOM is published. Both
  are reasonable next steps and neither is a prerequisite for a first release.
- **A support or deprecation policy for published versions.** Nothing here commits to
  keeping any version pullable for any period.
- **Publishing the Edge worker as a container.** It is not deployed that way.

## Rejected alternatives

**A public Docker Hub organisation.** It is where the deployment documents already
pointed, so it looked like the smallest change. It needs an organisation account, a
credential stored as a repository secret, and someone to own rotating it — all to
put the artifact somewhere other than where its source already is. Rate limits on
anonymous pulls are a second, smaller reason against.

**Reusing the private AWS registry.** It already builds and pushes these three
images. It is private, tied to one cloud account, and the images it holds are named
for a demo deployment. Making it public would mean publishing an operational
registry, which conflates our environment with the reference implementation's
artifacts.

**Nesting the image names under the repository**
(`ghcr.io/ramp-protocol/reference-implementation/exchange`). This is the registry's
default shape and needs no decision. It reads as though the repository were part of
the artifact's identity, and it makes every command in every deployment document
longer for no gain to the reader.
