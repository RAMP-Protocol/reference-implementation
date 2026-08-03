//go:build integration

package billing_test

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// latencyIterations is the per-method sample size.
const latencyIterations = 50

// latencyBudget is the per-call acceptance criterion for the billing
// adapter: each adapter call under 5 ms. The gate below asserts the per-op
// MEDIAN against latencyCeiling = latencyBudget * ciJitterMultiplier, tying the
// executable check to the documented budget instead of the previous bare 50 ms
// ceiling (10x the budget, which green-lit a ~10x regression while only logging
// the real number).
//
// ciJitterMultiplier is a small, named headroom over the budget. It is safe
// against the two inflation sources without flaking:
//   - the suite runs under -race, but these calls are TigerBeetle IPC
//     round-trips (measured medians ~2–4 ms), which the race detector — memory instrumentation —
//     inflates only marginally;
//   - the assertion is on the MEDIAN of latencyIterations samples, so a
//     transient noisy-neighbor spike on a shared runner cannot move it; only a
//     systemic slowdown (a real regression or a badly degraded host) pushes the
//     median past the ceiling.
const (
	latencyBudget      = 5 * time.Millisecond
	ciJitterMultiplier = 3
	latencyCeiling     = latencyBudget * ciJitterMultiplier
)

// TestTigerBeetleLatency measures per-call wall time for each adapter method
// against a co-located TigerBeetle. A TigerBeetle client session
// holds at most one in-flight request, so these serial single-op calls are the
// light-load per-call latency; batching is TigerBeetle's throughput lever, not a
// per-call-latency lever.
func TestTigerBeetleLatency(t *testing.T) {
	a, _ := splitAdapter(t)
	ctx := context.Background()
	samples := map[string][]time.Duration{}
	record := func(op string, d time.Duration) { samples[op] = append(samples[op], d) }

	for i := 0; i < latencyIterations; i++ {
		k := fmt.Sprintf("lat%d", i)
		bid, d := timedAuthorize(t, a, "0.02", "rec-"+k)
		record("Authorize", d)
		record("GetBalance", timed(func() { _, err := a.GetBalance(ctx, "ag"); mustNil(t, err) }))
		record("Record", timed(func() { mustNil(t, a.Record(ctx, bid, 1, "rec-"+k)) }))
		record("Refund", timed(func() {
			mustNil(t, a.Refund(ctx, bid, mustAmount(t, "0.01", "USD"), "lat", "ref-"+k))
		}))
		relBID, _ := timedAuthorize(t, a, "0.02", "rel-"+k)
		record("Release", timed(func() { mustNil(t, a.Release(ctx, relBID, "rel-"+k)) }))
	}

	for _, op := range []string{"Authorize", "Record", "Release", "Refund", "GetBalance"} {
		median, p95 := summarize(samples[op])
		t.Logf("tigerbeetle %-11s n=%d median=%v p95=%v", op, len(samples[op]), median, p95)
		if median > latencyCeiling {
			t.Errorf("%s median %v exceeds %v (%v budget × %d CI-jitter headroom)",
				op, median, latencyCeiling, latencyBudget, ciJitterMultiplier)
		}
	}
}

// timed returns the wall time fn takes to run.
func timed(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}

// timedAuthorize authorizes a charge under key and returns the BillingID and the
// call's wall time.
func timedAuthorize(t *testing.T, a billing.Adapter, cost, key string) (string, time.Duration) {
	t.Helper()
	start := time.Now()
	res, err := a.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, cost, "USD"), Quantity: 1,
		IdempotencyKey: key, ResourceOwnerID: splitOwner, FeeRateBps: splitFeeBps,
	})
	d := time.Since(start)
	if err != nil || !res.Approved {
		t.Fatalf("Authorize(%s) = (approved=%v, %v)", key, res.Approved, err)
	}
	return res.BillingID, d
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("adapter call: %v", err)
	}
}

// summarize returns the median and p95 of ds (n≥1).
func summarize(ds []time.Duration) (median, p95 time.Duration) {
	sorted := append([]time.Duration(nil), ds...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2], sorted[(len(sorted)*95)/100]
}
