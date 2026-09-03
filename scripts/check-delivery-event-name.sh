#!/usr/bin/env bash
# check-delivery-event-name.sh
#
# Structural guard on the one string that joins the edge worker to the ledger.
#
# The edge worker names its authorized-delivery record with a constant; the
# ledger renderer finds that record in the collected logs by searching for the
# same name. The two are written in different languages, so nothing but this
# check makes them agree.
#
# Drift here fails SILENTLY and in the worst possible direction: every chain
# still renders, the delivery and origin rows just come back "no delivery
# recorded", which reads as CloudWatch lag rather than as a bug. Both sides
# keep passing their own tests, because each is self-consistent.
#
# Exits 0 when both sides name the same event, 1 otherwise.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

worker_file="${repo_root}/src/edge/src/log.ts"
ledger_file="${repo_root}/src/broker/cmd/ramp-ledger/edgelog.go"

for f in "${worker_file}" "${ledger_file}"; do
    if [ ! -f "${f}" ]; then
        echo "FAIL  ${f#"${repo_root}/"} is missing; this guard cannot compare what it cannot read."
        echo "delivery-event-name guard: fix the path above before merging."
        exit 1
    fi
done

# Both sides declare the name as a single-quoted or double-quoted literal on the
# constant's own line, so one pattern per file reads it without a parser.
worker_event=$(sed -n "s/^export const DELIVERY_EVENT = '\([^']*\)';.*/\1/p" "${worker_file}")
ledger_event=$(sed -n 's/^const deliveryEvent = "\([^"]*\)".*/\1/p' "${ledger_file}")

if [ -z "${worker_event}" ]; then
    echo "FAIL  no DELIVERY_EVENT constant found in src/edge/src/log.ts."
    echo "      The guard reads it from a single line; if the declaration moved,"
    echo "      update this script rather than dropping the check."
    echo "delivery-event-name guard: fix the declaration above before merging."
    exit 1
fi

if [ -z "${ledger_event}" ]; then
    echo "FAIL  no deliveryEvent constant found in src/broker/cmd/ramp-ledger/edgelog.go."
    echo "      The guard reads it from a single line; if the declaration moved,"
    echo "      update this script rather than dropping the check."
    echo "delivery-event-name guard: fix the declaration above before merging."
    exit 1
fi

if [ "${worker_event}" != "${ledger_event}" ]; then
    echo "FAIL  the edge worker and the ledger name different delivery events:"
    echo "      src/edge/src/log.ts                       ${worker_event}"
    echo "      src/broker/cmd/ramp-ledger/edgelog.go     ${ledger_event}"
    echo ""
    echo "      The ledger finds a delivery by this name. While they disagree,"
    echo "      every evidence chain renders its delivery and origin rows as"
    echo "      'no delivery recorded' and nothing else reports the mismatch."
    echo "delivery-event-name guard: make the two agree before merging."
    exit 1
fi

echo "PASS  edge worker and ledger agree on the delivery event name (${worker_event})"
echo "delivery-event-name guard: all checks passed."
exit 0
