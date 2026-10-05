// Portability proof — HMAC-SHA256 signing + verification for the public
// /portability/proof endpoint.
//
// MVP: HMAC over (gcid, payload) with a server-side stub secret. Production
// wires Cloud KMS sign-blob with a per-tenant or per-platform CMEK key (ADR
// pending). The verification helper is constant-time-equal.
package portability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// SignProof returns a hex-encoded HMAC-SHA256 over (gcid || ":" || payload),
// keyed by `secret`. Returns an error if secret or gcid is empty.
func SignProof(secret []byte, gcid, payload string) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("secret is required")
	}
	if strings.TrimSpace(gcid) == "" {
		return "", errors.New("gcid is required")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(gcid))
	_, _ = mac.Write([]byte{':'})
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyProof reports whether `signature` (hex-encoded HMAC-SHA256) is a
// valid signature over (gcid, payload) under `secret`. Constant-time compare.
func VerifyProof(secret []byte, gcid, payload, signature string) bool {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return false
	}
	want, err := SignProof(secret, gcid, payload)
	if err != nil {
		return false
	}
	wantBytes, err := hex.DecodeString(want)
	if err != nil {
		return false
	}
	gotBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return hmac.Equal(wantBytes, gotBytes)
}
