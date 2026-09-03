package repo

// ObligationCounts and its accessors. Split from obligation.go so the file that
// owns the row mapping does not also own the compliance projection, and so the
// buckets keep their own home as reporting policy grows.

// ObligationCounts is the reporting-compliance fact table for one
// (tenant_id, agent_id): how many obligations sit in each state, split by
// whether the deadline had already passed at the instant asked about.
//
// It states what is there and judges nothing. Which bucket counts as "overdue",
// which ones form the denominator, and where any threshold sits are the
// Exchange's reporting policy, decided in the service — so a future per-tenant
// rule reads these same numbers differently without a new query. The buckets
// stay unexported so a caller cannot iterate them in whatever order the
// database returned; the two accessors below are the whole read surface.
type ObligationCounts struct {
	buckets map[obligationBucket]int64
}

type obligationBucket struct {
	state        ObligationState
	pastDeadline bool
}

// In returns how many obligations sit in one bucket. An absent bucket is zero,
// which is what "the agent has none of those" means.
func (c ObligationCounts) In(state ObligationState, pastDeadline bool) int64 {
	return c.buckets[obligationBucket{state: state, pastDeadline: pastDeadline}]
}

// PastDeadline returns the total across every state whose deadline had passed.
func (c ObligationCounts) PastDeadline() int64 {
	var total int64
	for bucket, n := range c.buckets {
		if bucket.pastDeadline {
			total += n
		}
	}
	return total
}
