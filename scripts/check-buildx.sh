#!/usr/bin/env bash
# Refuse to build the e2e stack with Docker's legacy builder.
#
# Compose falls back to it SILENTLY when the buildx plugin is missing: it prints
# one "Docker Compose requires buildx plugin to be installed" warning among
# thousands of build lines, then re-sends the whole build context per image and
# builds them one at a time. Measured on this repo's 19 images: 39 minutes on
# the legacy builder against 75 seconds on BuildKit, for the same command with
# the same sources. Nothing fails, so the only symptom is that a stack-up you
# expected to take a minute takes most of an hour.
#
# The check is on the PLUGIN rather than on any build output, because that is
# the thing that goes missing — a plugin directory mid-upgrade, a slimmed CI
# image, a docker install that never shipped it.
set -euo pipefail

if docker buildx version >/dev/null 2>&1; then
    exit 0
fi

cat >&2 <<'MSG'
FAIL  docker buildx is not available, so compose would build the e2e stack with
      the legacy builder: no parallel stages, no shared layer cache, and the
      full build context re-sent per image. That is ~39 minutes for this stack
      instead of ~75 seconds, with no error to say why.

      Install the plugin, then re-run:

        Arch/Manjaro   sudo pacman -S docker-buildx
        Debian/Ubuntu  sudo apt install docker-buildx-plugin
        manual         https://github.com/docker/buildx#manual-download
                       (drop docker-buildx into ~/.docker/cli-plugins/)

      Verify with `docker buildx version` before re-running.
MSG
exit 1
