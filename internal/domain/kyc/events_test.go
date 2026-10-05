// Tests for kyc event payload helpers.
package kyc_test

import (
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

func TestTopicName_AllEvents(t *testing.T) {
	t.Parallel()
	cases := map[kyc.EventType]string{
		kyc.EventSubmitted: "chora.identity.kyc.submitted.v1",
		kyc.EventVerified:  "chora.identity.kyc.verified.v1",
		kyc.EventRejected:  "chora.identity.kyc.rejected.v1",
	}
	for evt, want := range cases {
		if got := kyc.TopicName(evt); got != want {
			t.Errorf("TopicName(%q)=%q want %q", evt, got, want)
		}
	}
}

func TestSubmittedFrom_PopulatesFields(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: "g", Method: kyc.MethodManualDoc, Provider: "internal_review"})
	_ = v.Submit("gs://bucket/x", 999, "USD")
	p := kyc.SubmittedFrom(v)
	if p.VerificationID != v.VerificationID {
		t.Errorf("VerificationID mismatch")
	}
	if p.Method != "manual_doc" {
		t.Errorf("Method=%q", p.Method)
	}
	if p.FeeChargedCents != 999 {
		t.Errorf("FeeChargedCents=%d", p.FeeChargedCents)
	}
}

func TestVerifiedFrom_PreservesActor(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: "g", Method: kyc.MethodManualDoc, Provider: "internal_review"})
	_ = v.Submit("", 0, "")
	_ = v.Verify("admin-1", false)
	p := kyc.VerifiedFrom(v)
	if p.VerifiedByGcid != "admin-1" {
		t.Errorf("VerifiedByGcid=%q", p.VerifiedByGcid)
	}
}

func TestVerifiedFrom_NoVerifiedAt_ReturnsZero(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: "g", Method: kyc.MethodSingpass, Provider: "ndi"})
	p := kyc.VerifiedFrom(v)
	if !p.VerifiedAt.IsZero() {
		t.Errorf("VerifiedAt should be zero on pending verification")
	}
}

func TestRejectedFrom_PreservesFields(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: "g", Method: kyc.MethodManualDoc, Provider: "internal_review"})
	_ = v.Submit("gs://b/x", 999, "USD")
	_ = v.Reject("liveness_failed", "blurry selfie", false)
	p := kyc.RejectedFrom(v)
	if p.RejectionCode != "liveness_failed" {
		t.Errorf("RejectionCode=%q", p.RejectionCode)
	}
	if p.RetryAllowed {
		t.Errorf("RetryAllowed should be false")
	}
}

func TestSoftDelete_SetsDeletedAt(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: "g", Method: kyc.MethodSingpass, Provider: "ndi"})
	v.SoftDelete()
	if v.DeletedAt == nil {
		t.Errorf("DeletedAt should be set")
	}
	prior := v.DeletedAt
	v.SoftDelete()
	if v.DeletedAt != prior {
		t.Errorf("SoftDelete should be idempotent")
	}
}

func TestMarkExpired_Idempotent(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: "g", Method: kyc.MethodSingpass, Provider: "ndi"})
	_ = v.MarkExpired()
	first := v.UpdatedAt
	if err := v.MarkExpired(); err != nil {
		t.Fatalf("MarkExpired: %v", err)
	}
	if !v.UpdatedAt.Equal(first) {
		t.Errorf("MarkExpired should be idempotent")
	}
}

func TestKycMethod_Valid(t *testing.T) {
	t.Parallel()
	for _, m := range []kyc.Method{kyc.MethodSingpass, kyc.MethodSkillsFuture, kyc.MethodManualDoc} {
		if !m.Valid() {
			t.Errorf("%q.Valid()=false", m)
		}
	}
	if kyc.Method("retina").Valid() {
		t.Errorf("invalid method accepted")
	}
}

func TestDefaultFeeCents_Unknown(t *testing.T) {
	t.Parallel()
	if got := kyc.DefaultFeeCents(kyc.Method("unknown")); got != 0 {
		t.Errorf("DefaultFeeCents unknown=%d want 0", got)
	}
}
