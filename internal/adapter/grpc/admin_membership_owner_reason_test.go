// admin_membership_owner_reason_test.go: S7-B1, the tenancy ownership
// refusals must survive the gRPC hop as distinct sentinels.
//
// chora-tenancy answers three different refusals with FAILED_PRECONDITION:
// the membership is suspended, the member is the tenant's last owner, and the
// role replace would strip ownership. The status code alone cannot separate
// them, so each carries an errdetails.ErrorInfo reason. This adapter reads
// that reason; without it every ownership refusal would arrive at the H+
// roster wearing the suspension message, which is wrong in a way an admin
// cannot act on.
package grpcadapter

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// refusalWithReason builds the exact error shape chora-tenancy returns.
func refusalWithReason(t *testing.T, reason string) error {
	t.Helper()
	st, err := status.New(codes.FailedPrecondition, "refused").WithDetails(&errdetails.ErrorInfo{
		Reason: reason,
		Domain: "chora-tenancy",
	})
	if err != nil {
		t.Fatalf("build status: %v", err)
	}
	return st.Err()
}

func TestAdminMembershipUpserter_OwnerReasonsMapToDistinctSentinels(t *testing.T) {
	cases := []struct {
		reason string
		want   error
	}{
		{"LAST_OWNER_PROTECTED", httpadapter.ErrUpstreamLastOwnerProtected},
		{"OWNER_ROLE_PROTECTED", httpadapter.ErrUpstreamOwnerRoleProtected},
		{"MEMBERSHIP_SUSPENDED", httpadapter.ErrUpstreamMembershipSuspended},
	}
	for _, tc := range cases {
		t.Run("Remove/"+tc.reason, func(t *testing.T) {
			stub := &fakeUpsertStub{removeErr: refusalWithReason(t, tc.reason)}
			err := NewAdminMembershipUpserterFromStub(stub).
				RemoveMembershipByTenantID(context.Background(), enrolGCID, amuTenant)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
		t.Run("Replace/"+tc.reason, func(t *testing.T) {
			stub := &fakeUpsertStub{err: refusalWithReason(t, tc.reason)}
			_, err := NewAdminMembershipUpserterFromStub(stub).
				ReplaceMembershipByTenantID(context.Background(), enrolGCID, amuTenant, []string{"ADMIN"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A FAILED_PRECONDITION with no reason attached is an older tenancy build, or
// a refusal somebody added without a reason. It keeps the historical
// suspension mapping rather than becoming an ownership error: guessing here
// would tell an admin to hand over ownership for a problem that has nothing to
// do with ownership.
func TestAdminMembershipUpserter_UnlabelledRefusalStaysSuspended(t *testing.T) {
	stub := &fakeUpsertStub{removeErr: status.Error(codes.FailedPrecondition, "membership suspended")}
	err := NewAdminMembershipUpserterFromStub(stub).
		RemoveMembershipByTenantID(context.Background(), enrolGCID, amuTenant)
	if !errors.Is(err, httpadapter.ErrUpstreamMembershipSuspended) {
		t.Fatalf("err = %v, want ErrUpstreamMembershipSuspended", err)
	}
	if errors.Is(err, httpadapter.ErrUpstreamLastOwnerProtected) ||
		errors.Is(err, httpadapter.ErrUpstreamOwnerRoleProtected) {
		t.Errorf("an unlabelled refusal must not be reported as an ownership problem")
	}
}

// An unknown reason from a newer tenancy build must not be silently folded
// into the suspension arm either. It stays a suspension error for the caller,
// because that is the safest existing behaviour, but it must never be
// mistaken for one of the ownership refusals the roster renders specially.
func TestAdminMembershipUpserter_UnknownReasonIsNotAnOwnershipError(t *testing.T) {
	stub := &fakeUpsertStub{removeErr: refusalWithReason(t, "SOME_FUTURE_REFUSAL")}
	err := NewAdminMembershipUpserterFromStub(stub).
		RemoveMembershipByTenantID(context.Background(), enrolGCID, amuTenant)
	if errors.Is(err, httpadapter.ErrUpstreamLastOwnerProtected) ||
		errors.Is(err, httpadapter.ErrUpstreamOwnerRoleProtected) {
		t.Fatalf("err = %v; an unrecognised reason must not claim to be an ownership refusal", err)
	}
	if err == nil {
		t.Fatalf("an unrecognised refusal must still be an error")
	}
}
