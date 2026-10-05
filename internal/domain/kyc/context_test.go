package kyc

import (
	"context"
	"testing"
)

func TestSubjectGcid_RoundTrip(t *testing.T) {
	const g = "00000000-0000-7000-8000-000000002042"
	ctx := WithSubjectGcid(context.Background(), g)
	if got := SubjectGcidFromContext(ctx); got != g {
		t.Fatalf("SubjectGcidFromContext = %q, want %q", got, g)
	}
}

func TestSubjectGcid_Absent_ReturnsEmpty(t *testing.T) {
	if got := SubjectGcidFromContext(context.Background()); got != "" {
		t.Fatalf("SubjectGcidFromContext on bare ctx = %q, want empty", got)
	}
}
