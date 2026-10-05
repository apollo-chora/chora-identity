// gap_test.go — internal-package coverage for the identity domain's
// remaining unexported helpers + aggregate branch paths (pending-invite
// role strings, AGID detection, WebAuthn CBOR primitives, attestation
// cert-extraction, KYC-terminal/expiry branches).
//
// The external identity_test suite covers the public API surface; this file
// targets the private helpers and the branch paths that need direct control
// of aggregate state.
package identity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// PendingInvite helpers
// -----------------------------------------------------------------------------

func TestRoleStrings_ReturnsLowercaseTokens(t *testing.T) {
	t.Parallel()
	pi := &PendingInvite{
		Roles: []Role{RoleLearner, RoleInstructor},
	}
	got := pi.RoleStrings()
	if len(got) != 2 || got[0] != "learner" || got[1] != "instructor" {
		t.Errorf("RoleStrings() = %v, want [learner instructor]", got)
	}
}

func TestRoleStrings_EmptyRoles(t *testing.T) {
	t.Parallel()
	pi := &PendingInvite{}
	got := pi.RoleStrings()
	if len(got) != 0 {
		t.Errorf("RoleStrings() = %v, want empty", got)
	}
}

func TestLooksLikeEmail_Branches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"alice@chora.dev", true},
		{"", false},
		{"@chora.dev", false},       // empty local part
		{"alice@", false},           // empty domain
		{"alice@@chora.dev", false}, // double @
		{"alice@chora", false},      // domain without dot
		{"alice@.chora.dev", false}, // domain leading dot
		{"alice@chora.dev.", false}, // domain trailing dot
	}
	for _, c := range cases {
		if got := looksLikeEmail(c.in); got != c.want {
			t.Errorf("looksLikeEmail(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// WebAuthn CBOR primitives
// -----------------------------------------------------------------------------

func TestDecodeCBORValue_UintIntAndBytes(t *testing.T) {
	t.Parallel()
	// uint 1
	v, n, err := decodeCBORValue([]byte{0x01})
	if err != nil || v.major != 0 || v.uval != 1 || n != 1 {
		t.Errorf("uint: v=%+v n=%d err=%v", v, n, err)
	}
	// negative int -1 (0x20)
	v, n, err = decodeCBORValue([]byte{0x20})
	if err != nil || v.major != 1 || !v.neg || n != 1 {
		t.Errorf("negative: v=%+v n=%d err=%v", v, n, err)
	}
	// byte string (0x42 "hi")
	v, n, err = decodeCBORValue([]byte{0x42, 'h', 'i'})
	if err != nil || v.major != 2 || string(v.bytes) != "hi" || n != 3 {
		t.Errorf("bytes: v=%+v n=%d err=%v", v, n, err)
	}
}

func TestDecodeCBORValue_Errors(t *testing.T) {
	t.Parallel()
	// Truncated byte string announces 3 bytes but only 1 present.
	if _, _, err := decodeCBORValue([]byte{0x43, 'x'}); !errors.Is(err, ErrMalformedCOSEKey) {
		t.Errorf("truncated byte string: err=%v, want ErrMalformedCOSEKey", err)
	}
	// Major 3 (text string) unsupported by this decoder.
	if _, _, err := decodeCBORValue([]byte{0x63, 'a', 'b', 'c'}); !errors.Is(err, ErrMalformedCOSEKey) {
		t.Errorf("text string major: err=%v, want ErrMalformedCOSEKey", err)
	}
	// Malformed head (additional info 31 = indefinite).
	if _, _, err := decodeCBORValue([]byte{0x1f}); err == nil {
		t.Error("indefinite-length head must error")
	}
}

func TestCBORValue_AsInt(t *testing.T) {
	t.Parallel()
	if got, ok := (cborValue{major: 0, uval: 42}).asInt(); !ok || got != 42 {
		t.Errorf("uint asInt = (%d, %v), want (42, true)", got, ok)
	}
	if got, ok := (cborValue{major: 1, uval: 1}).asInt(); !ok || got != -2 {
		t.Errorf("nint asInt = (%d, %v), want (-2, true)", got, ok)
	}
	if _, ok := (cborValue{major: 2}).asInt(); ok {
		t.Error("byte-string asInt must report false")
	}
}

func TestCBORSkipValue_AllMajors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
		want int
	}{
		{"uint", []byte{0x01}, 1},
		{"byte string", []byte{0x42, 'h', 'i'}, 3},
		{"text string", []byte{0x63, 'a', 'b', 'c'}, 4},
		{"tag", []byte{0xc1, 0x18, 0x64}, 3}, // tag 1 wrapping 100
		{"array empty", []byte{0x80}, 1},
		{"array 2 items", []byte{0x82, 0x01, 0x02}, 3},
		{"map 1 pair", []byte{0xa1, 0x01, 0x02}, 3},
		{"simple 7", []byte{0xf6}, 1}, // null
		{"float16", []byte{0xf9, 0x3c, 0x00}, 3},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := cborSkipValue(c.in)
			if err != nil {
				t.Fatalf("cborSkipValue: %v", err)
			}
			if got != c.want {
				t.Errorf("cborSkipValue(% x) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

func TestCBORSkipValue_Errors(t *testing.T) {
	t.Parallel()
	if _, err := cborSkipValue([]byte{0x9f}); err == nil {
		t.Error("indefinite array head must error")
	}
	if _, err := cborSkipValue([]byte{0x42, 0x01}); err == nil {
		t.Error("truncated string must error")
	}
	if _, err := cborSkipValue(nil); err == nil {
		t.Error("empty input must error")
	}
	if _, err := cborSkipValue([]byte{0x9f, 0x00}); err == nil {
		t.Error("indefinite-length must error at head")
	}
}

// -----------------------------------------------------------------------------
// Attestation helpers
// -----------------------------------------------------------------------------

func TestAAGUIDFromCert_ExtractsExtension(t *testing.T) {
	t.Parallel()
	aaguid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wrapped, err := asn1.Marshal(aaguid)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	cert := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: fidoAAGUIDCertExtOID, Value: wrapped}},
	}
	got, ok := aaguidFromCert(cert)
	if !ok {
		t.Fatal("aaguidFromCert did not find the extension")
	}
	if string(got) != string(aaguid) {
		t.Errorf("aaguid = % x, want % x", got, aaguid)
	}
}

func TestAAGUIDFromCert_MissingAndMalformed(t *testing.T) {
	t.Parallel()
	if _, ok := aaguidFromCert(&x509.Certificate{}); ok {
		t.Error("cert without extension must report not-found")
	}
	// Wrong OID is ignored.
	other := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{0x05, 0x00}}},
	}
	if _, ok := aaguidFromCert(other); ok {
		t.Error("cert with unrelated extension must report not-found")
	}
	// Extension with garbage ASN.1 payload → not-found.
	bad := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: fidoAAGUIDCertExtOID, Value: []byte{0xff, 0xff}}},
	}
	if _, ok := aaguidFromCert(bad); ok {
		t.Error("malformed extension payload must report not-found")
	}
}

func TestCertLevelRank_UppercasesAndParses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want int
	}{
		{"L2", 2},
		{"l3", 3},
		{" L1 ", 1},
		{"L", 0},
		{"Lx", 0},
		{"", 0},
		{"0", 0},
	}
	for _, c := range cases {
		if got := certLevelRank(c.in); got != c.want {
			t.Errorf("certLevelRank(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// PasskeyChallenge / PasskeyCredential branch paths
// -----------------------------------------------------------------------------

// expiredChallenge builds a challenge whose ExpiresAt lies in the past.
func expiredChallenge() *PasskeyChallenge {
	return &PasskeyChallenge{
		ChallengeID:    "ch-0",
		ChallengeBytes: make([]byte, 32),
		RPID:           "chora.app",
		Status:         PasskeyChallengeStatusPending,
		CreatedAt:      time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt:      time.Now().UTC().Add(-time.Hour),
	}
}

func TestPasskeyChallenge_MarkVerified_ExpiredFailsLoud(t *testing.T) {
	t.Parallel()
	c := expiredChallenge()
	err := c.MarkVerified("01970000-0000-7000-8000-000000000001")
	if !errors.Is(err, ErrPasskeyChallengeExpired) {
		t.Fatalf("MarkVerified on expired challenge: err=%v, want ErrPasskeyChallengeExpired", err)
	}
	if c.Status != PasskeyChallengeStatusExpired {
		t.Errorf("status = %q, want expired", c.Status)
	}
}

func TestPasskeyChallenge_MarkVerified_ConsumedFailsLoud(t *testing.T) {
	t.Parallel()
	c := &PasskeyChallenge{
		ChallengeID:    "ch-1",
		ChallengeBytes: make([]byte, 32),
		RPID:           "chora.app",
		Status:         PasskeyChallengeStatusConsumed,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}
	if err := c.MarkVerified("01970000-0000-7000-8000-000000000001"); !errors.Is(err, ErrPasskeyChallengeConsumed) {
		t.Errorf("MarkVerified on consumed: err=%v, want ErrPasskeyChallengeConsumed", err)
	}
}

func TestPasskeyChallenge_MarkVerified_RejectsDifferentGcid(t *testing.T) {
	t.Parallel()
	c := &PasskeyChallenge{
		ChallengeID:    "ch-2",
		ChallengeBytes: make([]byte, 32),
		RPID:           "chora.app",
		Status:         PasskeyChallengeStatusVerified,
		VerifiedGCID:   "01970000-0000-7000-8000-000000000001",
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}
	if err := c.MarkVerified("01970000-0000-7000-8000-000000000002"); err == nil {
		t.Error("MarkVerified with a different gcid must error")
	}
	// Same gcid is idempotent.
	if err := c.MarkVerified("01970000-0000-7000-8000-000000000001"); err != nil {
		t.Errorf("MarkVerified same gcid: %v", err)
	}
}

func TestPasskeyChallenge_MarkConsumed_Idempotent(t *testing.T) {
	t.Parallel()
	c := &PasskeyChallenge{Status: PasskeyChallengeStatusConsumed}
	if err := c.MarkConsumed(); err != nil {
		t.Errorf("MarkConsumed on consumed must be a no-op: %v", err)
	}
}

func TestPasskeyCredential_NewRejectsInvariants(t *testing.T) {
	t.Parallel()
	base := NewPasskeyCredentialParams{
		Gcid:          "01970000-0000-7000-8000-000000000001",
		CredentialID:  []byte{1, 2, 3},
		PublicKeyCOSE: []byte{0xa4},
		RPID:          "chora.app",
	}
	if _, err := NewPasskeyCredential(base); err != nil {
		t.Fatalf("valid params: %v", err)
	}
	// AGID gcid rejected.
	agid := base
	agid.Gcid = "0197a000-0000-7000-8000-000000000001"
	if _, err := NewPasskeyCredential(agid); err == nil {
		t.Error("AGID gcid must be rejected")
	}
	// Empty credential id.
	noCred := base
	noCred.CredentialID = nil
	if _, err := NewPasskeyCredential(noCred); err == nil {
		t.Error("empty credential_id must be rejected")
	}
	// Empty COSE key.
	noKey := base
	noKey.PublicKeyCOSE = nil
	if _, err := NewPasskeyCredential(noKey); err == nil {
		t.Error("empty public_key_cose must be rejected")
	}
	// Empty RPID.
	noRPID := base
	noRPID.RPID = "  "
	if _, err := NewPasskeyCredential(noRPID); err == nil {
		t.Error("blank rp_id must be rejected")
	}
	// Empty attestation type defaults to "none".
	att := base
	att.AttestationType = ""
	cred, err := NewPasskeyCredential(att)
	if err != nil {
		t.Fatalf("default attestation: %v", err)
	}
	if cred.AttestationType != "none" {
		t.Errorf("AttestationType = %q, want none", cred.AttestationType)
	}
}

func TestPasskeyCredential_RecordUse_Branches(t *testing.T) {
	t.Parallel()
	// Revoked credential refuses every use.
	revoked := &PasskeyCredential{Status: PasskeyCredentialStatusRevoked, SignCount: 5}
	if err := revoked.RecordUse(6); !errors.Is(err, ErrPasskeyCredentialReplay) && err == nil {
		t.Error("RecordUse on revoked must error")
	}
	// 0/0 authenticator (no counter) is accepted.
	zero := &PasskeyCredential{Status: PasskeyCredentialStatusActive, SignCount: 0}
	if err := zero.RecordUse(0); err != nil {
		t.Errorf("RecordUse(0) on 0 counter: %v", err)
	}
	// Replay (counter regression) is an attack.
	replay := &PasskeyCredential{Status: PasskeyCredentialStatusActive, SignCount: 5}
	if err := replay.RecordUse(4); !errors.Is(err, ErrPasskeyCredentialReplay) {
		t.Errorf("counter regression: err=%v, want ErrPasskeyCredentialReplay", err)
	}
	// Monotonic increase succeeds.
	ok := &PasskeyCredential{Status: PasskeyCredentialStatusActive, SignCount: 5}
	if err := ok.RecordUse(6); err != nil {
		t.Errorf("RecordUse(6): %v", err)
	}
	if ok.SignCount != 6 {
		t.Errorf("SignCount = %d, want 6", ok.SignCount)
	}
}

func TestPasskeyCredential_Revoke_Idempotent(t *testing.T) {
	t.Parallel()
	c := &PasskeyCredential{Status: PasskeyCredentialStatusRevoked}
	c.Revoke() // second call must not panic / no-op
	if c.Status != PasskeyCredentialStatusRevoked {
		t.Errorf("status = %q, want revoked", c.Status)
	}
}

// -----------------------------------------------------------------------------
// User KYC terminal branches + portable snapshot invariants
// -----------------------------------------------------------------------------

func TestUser_MarkKycPendingAndRejectedIdempotent(t *testing.T) {
	t.Parallel()
	u := &User{VerificationStatus: VerificationStatusPending, KycMethod: KycMethod("singpass")}
	u.MarkKycPending(KycMethod("singpass")) // same (method) → no-op
	if u.VerificationStatus != VerificationStatusPending {
		t.Errorf("status = %q, want pending", u.VerificationStatus)
	}
	u.MarkKycPending(KycMethod("manual_doc")) // different method flips
	if u.KycMethod != KycMethod("manual_doc") {
		t.Errorf("method = %q, want manual", u.KycMethod)
	}
	u.MarkKycRejected()
	u.MarkKycRejected() // idempotent
	if u.VerificationStatus != VerificationStatusRejected {
		t.Errorf("status = %q, want rejected", u.VerificationStatus)
	}
}

func TestLooseValidEmail_Branches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"alice@chora.dev", true},
		{"", false},
		{"@chora.dev", false},
		{"alice@", false},
		{"alice@chora", false},
		{"a@b@chora.dev", false},
	}
	for _, c := range cases {
		if got := LooseValidEmail(c.in); got != c.want {
			t.Errorf("LooseValidEmail(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNewPortableSnapshot_RejectsInvariants(t *testing.T) {
	t.Parallel()
	if _, err := NewPortableSnapshot(NewPortableSnapshotParams{Gcid: "", Sequence: 1, PayloadHash: "h"}); err == nil {
		t.Error("empty gcid must be rejected")
	}
	if _, err := NewPortableSnapshot(NewPortableSnapshotParams{Gcid: "g-1", Sequence: 0, PayloadHash: "h"}); err == nil {
		t.Error("sequence < 1 must be rejected")
	}
	if _, err := NewPortableSnapshot(NewPortableSnapshotParams{Gcid: "g-1", Sequence: 1}); err == nil {
		t.Error("empty payload_hash must be rejected")
	}
	snap, err := NewPortableSnapshot(NewPortableSnapshotParams{Gcid: "g-1", Sequence: 2, PayloadHash: "h"})
	if err != nil {
		t.Fatalf("valid snapshot: %v", err)
	}
	snap.AppendOnlyMarker() // documentation guard — must be a no-op
	if snap.Sequence != 2 {
		t.Errorf("Sequence = %d, want 2", snap.Sequence)
	}
}

// -----------------------------------------------------------------------------
// WebAuthn CBOR decoder error branches (malformed COSE keys + attestation
// objects) — direct internal calls keep the fixtures tiny.
// -----------------------------------------------------------------------------

func TestDecodeCBORHead_AllLengthEncodings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		in    []byte
		major byte
		arg   uint64
		n     int
	}{
		{"short", []byte{0x05}, 0, 5, 1},
		{"8bit", []byte{0x18, 0xff}, 0, 0xff, 2},
		{"16bit", []byte{0x19, 0x01, 0x02}, 0, 0x0102, 3},
		{"32bit", []byte{0x1a, 0x01, 0x02, 0x03, 0x04}, 0, 0x01020304, 5},
		{"64bit", []byte{0x1b, 1, 2, 3, 4, 5, 6, 7, 8}, 0, 0x0102030405060708, 9},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			major, arg, n, err := decodeCBORHead(c.in)
			if err != nil || major != c.major || arg != c.arg || n != c.n {
				t.Errorf("decodeCBORHead(% x) = (%d, %d, %d, %v), want (%d, %d, %d, nil)",
					c.in, major, arg, n, err, c.major, c.arg, c.n)
			}
		})
	}
}

func TestDecodeCBORHead_TruncatedAndIndefinite(t *testing.T) {
	t.Parallel()
	bads := [][]byte{
		nil,
		{0x18},          // 8-bit arg missing
		{0x19, 0x01},    // 16-bit arg truncated
		{0x1a, 1, 2},    // 32-bit arg truncated
		{0x1b, 1, 2, 3}, // 64-bit arg truncated
		{0x1f},          // indefinite-length uint
		{0x3f},          // indefinite-length text
	}
	for i, in := range bads {
		if _, _, _, err := decodeCBORHead(in); !errors.Is(err, ErrMalformedCOSEKey) {
			t.Errorf("case %d (% x): err=%v, want ErrMalformedCOSEKey", i, in, err)
		}
	}
}

func TestParseCOSEKey_MalformedMaps(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
	}{
		{"not a map", []byte{0x01}},
		{"non-int key", []byte{0xa1, 0x42, 0x01, 0x02, 0x01}},
		{"kty not int", []byte{0xa1, 0x01, 0x42, 0x01, 0x02}},
		{"missing kty or alg", []byte{0xa1, 0x01, 0x02}},
		{"truncated value", []byte{0xa1, 0x01}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := parseCOSEKey(c.in); !errors.Is(err, ErrMalformedCOSEKey) {
				t.Errorf("parseCOSEKey(% x) err=%v, want ErrMalformedCOSEKey", c.in, err)
			}
		})
	}
}

func TestParseAttestationObject_Malformed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
	}{
		{"not a map", []byte{0x01}},
		{"non-text key", []byte{0xa1, 0x01, 0x01}},
		{"truncated key", []byte{0xa1, 0x63, 0x61}},
		{"fmt not text", []byte{0xa1, 0x63, 0x66, 0x6d, 0x74, 0x01}},
		{"truncated fmt", []byte{0xa1, 0x63, 0x66, 0x6d, 0x74, 0x64, 0x61}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseAttestationObject(c.in); !errors.Is(err, ErrMalformedAttestation) {
				t.Errorf("ParseAttestationObject(% x) err=%v, want ErrMalformedAttestation", c.in, err)
			}
		})
	}
}

func TestCBORSkipValue_ReservedMajorsRejected(t *testing.T) {
	t.Parallel()
	if _, err := cborSkipValue([]byte{0xf8}); err == nil {
		t.Error("major 7 with reserved additional info must error")
	}
	if _, err := cborSkipValue([]byte{0x78, 0x02, 'a'}); err == nil {
		t.Error("truncated text string must error")
	}
}
