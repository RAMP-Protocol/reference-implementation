package repo

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsUnavailable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"context canceled", context.Canceled, true},
		{"connect error", &pgconn.ConnectError{}, true},
		{"connection exception (08)", &pgconn.PgError{Code: "08006"}, true},
		{"too many connections (53)", &pgconn.PgError{Code: "53300"}, true},
		{"admin shutdown (57)", &pgconn.PgError{Code: "57P01"}, true},
		{"unique violation (23)", &pgconn.PgError{Code: "23505"}, false},
		{"wrapped connect error", fmt.Errorf("query: %w", &pgconn.ConnectError{}), true},
		{"plain error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isUnavailable(tc.err); got != tc.want {
				t.Fatalf("isUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
