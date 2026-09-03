#!/usr/bin/env bash
# deployment-docs.sh — the single definition of which deployment documents
# declare the published container-image version.
#
# Sourced, never executed. Defines one array and nothing else: no side effects,
# no output, no `set` changes.
#
# WHY IT EXISTS. Each of these documents declares the version once, in a
# `VERSION=` line, and every docker command in the document reuses it. Two tools
# act on that list: the image-version gate, which requires exactly one
# declaration per document and requires them all to agree, and the release tool
# that rewrites those lines (the latter is not part of the published set, so it
# is not named here). They used to hold a copy each, and nothing compared the
# two.
#
# The drift that mattered was silent. A document listed by the release tool but
# not by the gate got rewritten and then never checked: it could name a version
# nobody published and the gate would report PASS, because it did not know the
# document existed. Rule 1 of the gate does not catch it either, since the
# document's commands use the sanctioned `:$VERSION` form. The reverse case was
# always loud — a document the gate lists and the release tool does not is left
# stale, and the agreement check fails on the next run.
#
# WHAT IS STILL WRITTEN OUT SEPARATELY, and why neither can read this file:
#
#   - the publishing workflow's build matrix under .github/workflows/. It
#     carries different data — a service name and a Dockerfile path — and GitHub
#     Actions YAML cannot source a shell file. A fourth service is still two
#     edits: this array and that matrix.
#   - the harness fixture that tests the gate. It keeps its own copy on purpose:
#     a fixture derived from the thing it tests agrees with a bug in it, and
#     then proves nothing. Do not "fix" that one.
#
# HOW THE GATE FINDS THIS FILE. It sources the copy sitting beside itself, not
# one belonging to the tree it was pointed at. So a gate run against another
# tree with `--root` applies THIS tree's list, and a document that exists only
# in the other tree goes unread. Nothing in this repository runs it that way —
# the Makefile passes no `--root` — and the sibling reference gate resolves its
# own shared definition identically. The release tool is the other case: it
# reads the copy in the repository it was invoked in, because it edits that
# tree's documents and runs that tree's gate.

# The services that ship a container image, in the order a reader meets them.
# Adding one here is half the change; the workflow matrix above is the other
# half.
DEPLOYMENT_DOCS=(
  src/exchange/DEPLOYMENT.md
  src/broker/DEPLOYMENT.md
  src/identity/DEPLOYMENT.md
)
