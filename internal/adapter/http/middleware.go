// Package httpadapter wires net/http handlers to the Identity domain.
//
// Middleware:
//   - logging: per-request method/path log + structured trace correlation.
//   - tenantContext: extracts X-Tenant-Id and gcid from headers; rejects
//     /api/* requests that lack either.
package httpadapter

import (
	"context"
	"log"
	"net/http"
	"strings"
)

type ctxKey string

const (
	ctxKeyTenantID ctxKey = "tenant_id"
	ctxKeyGcid     ctxKey = "gcid"
	ctxKeyReqID    ctxKey = "request_id"
)

// tenantContext extracts tenant_id + gcid from headers and stores them on the
// request context. Rejects protected paths (/api/*) that omit either header
// with HTTP 400 + a JSON error envelope.
func tenantContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health endpoints bypass tenant extraction.
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
		gcid := strings.TrimSpace(r.Header.Get("gcid"))
		if gcid == "" {
			gcid = strings.TrimSpace(r.Header.Get("X-Chora-GCID"))
		}

		if tenantID == "" {
			writeError(w, http.StatusBadRequest, "IDENTITY_TENANT_REQUIRED",
				"X-Tenant-Id header is required")
			return
		}
		if gcid == "" {
			writeError(w, http.StatusBadRequest, "IDENTITY_GCID_REQUIRED",
				"gcid header is required")
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, ctxKeyTenantID, tenantID)
		ctx = context.WithValue(ctx, ctxKeyGcid, gcid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// logging logs each request once it has dispatched. Includes W3C traceparent
// correlation when present (per Tier 3 D13).
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gcid := r.Header.Get("gcid")
		if gcid == "" {
			gcid = r.Header.Get("X-Chora-GCID")
		}
		traceparent := r.Header.Get("traceparent")
		if traceparent != "" {
			log.Printf("method=%s path=%s gcid=%s traceparent=%s", r.Method, r.URL.Path, gcid, traceparent)
		} else if gcid != "" {
			log.Printf("method=%s path=%s gcid=%s", r.Method, r.URL.Path, gcid)
		} else {
			log.Printf("method=%s path=%s", r.Method, r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}

func isPublicPath(p string) bool {
	switch p {
	case "/", "/healthz", "/healthz/", "/health", "/readyz":
		return true
	}
	// /me + /me/roles use bearer auth, not the X-Tenant-Id/gcid header pair.
	if p == "/me" || p == "/me/roles" || strings.HasPrefix(p, "/me/") {
		return true
	}
	return false
}

// tenantFromContext returns the tenant_id stored by tenantContext; empty if absent.
func tenantFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyTenantID).(string)
	return v
}

// gcidFromContext returns the gcid stored by tenantContext; empty if absent.
func gcidFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyGcid).(string)
	return v
}
