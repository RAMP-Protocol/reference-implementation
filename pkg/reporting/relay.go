// Package reporting provides components for relaying usage reports and managing obligations.
package reporting

import (
    "context"
    "errors"
    "net/http"
    "time"
)

// Obligation tracks a reporting obligation for a transaction.
type Obligation struct {
    TransactionID  string
    BillingID      string
    TargetExchange string
    Required       bool
    Deadline       time.Time
    Fulfilled      bool
    FulfilledAt    time.Time
}

// Relay forwards UsageReports to the correct Exchange and manages obligations.
type Relay struct {
    // client is used to forward reports to Exchanges.
    client HTTPClient
    // store persists obligations.
    store ObligationStore
    // logger records relay attempts.
    logger Logger
    // metrics collects operational metrics.
    metrics Metrics
}

// HTTPClient defines the interface for making HTTP requests to Exchanges.
type HTTPClient interface {
    Do(req *http.Request) (*http.Response, error)
}

// ObligationStore defines the interface for obligation persistence.
type ObligationStore interface {
    GetPending(ctx context.Context, deadlineBefore time.Time) ([]Obligation, error)
    GetByTransaction(ctx context.Context, transactionID string) (*Obligation, error)
    MarkFulfilled(ctx context.Context, transactionID string, fulfilledAt time.Time) error
    Create(ctx context.Context, ob Obligation) error
}

// Logger defines the interface for structured logging.
type Logger interface {
    Info(msg string, fields map[string]interface{})
    Error(msg string, fields map[string]interface{})
}

// Metrics defines the interface for recording metrics.
type Metrics interface {
    IncRelayAttempt(success bool)
    ObserveRelayLatency(duration time.Duration)
    IncObligationDeadlineApproaching()
}

// UsageReport and UsageReportResponse are placeholders for the actual protocol types.
type UsageReport struct {
    TransactionID string
    BillingID     string
    // ... other fields (consumed_quantity, consumed_unit, function, subfn, attribution details)
}

type UsageReportResponse struct {
    // ... fields from Exchange response
}

var (
    ErrUnknownTransaction = errors.New("unknown transaction")
    ErrAlreadyFulfilled   = errors.New("obligation already fulfilled")
)

// ForwardUsageReport forwards the given UsageReport to the target Exchange.
// It validates the transaction, ensures the obligation exists, forwards the
// report byte-identical, records the attempt, and updates the obligation on success.
func (r *Relay) ForwardUsageReport(ctx context.Context, report UsageReport) (*UsageReportResponse, error) {
    // 1. Retrieve obligation for this transaction.
    ob, err := r.store.GetByTransaction(ctx, report.TransactionID)
    if err != nil {
        return nil, err
    }
    if ob == nil {
        return nil, ErrUnknownTransaction
    }
    if ob.Fulfilled {
        return nil, ErrAlreadyFulfilled
    }

    // 2. Forward the report to the target Exchange.
    start := time.Now()
    resp, err := r.forward(ctx, report, ob.TargetExchange)
    latency := time.Since(start)

    // 3. Record metrics and log attempt.
    r.metrics.ObserveRelayLatency(latency)
    fields := map[string]interface{}{
        "transaction_id":   report.TransactionID,
        "target_exchange":  ob.TargetExchange,
        "success":          err == nil,
        "latency_ms":       latency.Milliseconds(),
    }
    if err != nil {
        r.metrics.IncRelayAttempt(false)
        r.logger.Error("relay attempt failed", fields)
        return nil, err
    }
    r.metrics.IncRelayAttempt(true)
    r.logger.Info("relay attempt succeeded", fields)

    // 4. Mark obligation fulfilled.
    if err := r.store.MarkFulfilled(ctx, report.TransactionID, time.Now()); err != nil {
        // Log but don't fail the response because the Exchange already accepted.
        r.logger.Error("failed to mark obligation fulfilled", map[string]interface{}{
            "transaction_id": report.TransactionID,
            "error":          err.Error(),
        })
    }

    return resp, nil
}

// forward performs the actual HTTP request to the Exchange.
func (r *Relay) forward(ctx context.Context, report UsageReport, targetExchange string) (*UsageReportResponse, error) {
    // Implementation details omitted for brevity.
    // Should preserve byte-identical payload, include original transaction_id and billing_id,
    // and return the Exchange's response or rejection reason.
    // TODO: implement HTTP call with appropriate headers and marshalling.
    return nil, nil
}

// CheckDeadlines scans for obligations whose deadline is within the next hour
// and logs/metrics them for alerting.
func (r *Relay) CheckDeadlines(ctx context.Context) error {
    deadline := time.Now().Add(time.Hour)
    pending, err := r.store.GetPending(ctx, deadline)
    if err != nil {
        return err
    }
    for _, ob := range pending {
        r.metrics.IncObligationDeadlineApproaching()
        r.logger.Info("obligation deadline approaching", map[string]interface{}{
            "transaction_id": ob.TransactionID,
            "deadline":       ob.Deadline,
        })
    }
    return nil
}
