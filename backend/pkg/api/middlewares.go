// Copyright 2022 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file https://github.com/redpanda-data/redpanda/blob/dev/licenses/bsl.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloudhut/common/rest"

	"github.com/go-chi/chi/v5"

	"github.com/redpanda-data/console/backend/pkg/auth/oidc"
)

// BasePathCtxKey is a helper to avoid allocations, idea taken from chi
var BasePathCtxKey = &struct{ name string }{"ConsoleURLPrefix"}

type basePathMiddleware struct {
	// basePath is the static base path that shall be applied.
	basePath string
	// useDynamicBasePathFromHeaders inherits the base-path from the X-Forwarded-Prefix header.
	useDynamicBasePathFromHeaders bool
	// If a base-path is set (either by the 'base-path' setting, or by the 'X-Forwarded-Prefix' header),
	// they will be removed from the request url. You probably want to leave this enabled, unless you
	// are using a proxy that can remove the prefix automatically (like Traefik's 'StripPrefix' option)
	stripPrefix bool
}

func newBasePathMiddleware(basePath string, useDynamicBasePathFromHeaders, stripPrefix bool) *basePathMiddleware {
	return &basePathMiddleware{
		basePath:                      basePath,
		useDynamicBasePathFromHeaders: useDynamicBasePathFromHeaders,
		stripPrefix:                   stripPrefix,
	}
}

// Wrap implements the middleware interface. It propagates the basePath that shall be used
// to the frontend by injecting it into the HTML as a variable. The frontend therefore knows
// the to be used basePath without sending an HTTP request.
// The basePath can be either a static configuration or dynamically set based on the
// request header 'X-Forwarded-Prefix'.
// Additionally, it may be in charge of stripping the prefix from any requests.
func (b *basePathMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := b.basePath
		if b.useDynamicBasePathFromHeaders && r.Header.Get("X-Forwarded-Prefix") != "" {
			prefix = r.Header.Get("X-Forwarded-Prefix")
		}
		if prefix == "" {
			next.ServeHTTP(w, r)
			return
		}

		// ensure correct prefix slashes
		prefix = ensurePrefixFormat(prefix)

		// Store prefix in context so handle_frontend can use it to inject it into the html
		r = r.WithContext(context.WithValue(r.Context(), BasePathCtxKey, prefix))

		if !b.stripPrefix {
			next.ServeHTTP(w, r)
			return
		}

		// Strip prefix from the request url
		var path string
		rctx := chi.RouteContext(r.Context())
		switch {
		case rctx.RoutePath != "":
			path = rctx.RoutePath
		case r.URL.RawPath != "":
			path = r.URL.RawPath
		default:
			path = r.URL.Path
		}

		// route path
		if after, ok := strings.CutPrefix(path, prefix); ok {
			rctx.RoutePath = "/" + after
		}

		// URL.path
		if after, ok := strings.CutPrefix(r.URL.Path, prefix); ok {
			r.URL.Path = "/" + after
		}

		// URL.RawPath
		if after, ok := strings.CutPrefix(r.URL.RawPath, prefix); ok {
			r.URL.RawPath = "/" + after
		}

		// requestURI
		if after, ok := strings.CutPrefix(r.RequestURI, prefix); ok {
			r.RequestURI = "/" + after
		}
		next.ServeHTTP(w, r)
	})
}

// auditLogMiddleware logs an audit entry for mutating REST API requests
// (POST, PUT, PATCH, DELETE), mirroring the fields produced by the Connect AuditLogInterceptor.
func auditLogMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				// fall through to audit logging
			default:
				next.ServeHTTP(w, r)
				return
			}

			ww := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(ww, r)

			attrs := []slog.Attr{
				slog.String("action", actionFromMethod(r.Method)),
				slog.String("peer_address", r.RemoteAddr),
				slog.String("status", strconv.Itoa(ww.statusCode)),
			}

			if rt := resourceTypeFromPath(r.URL.Path); rt != "" {
				attrs = append(attrs, slog.String("resource_type", rt))
			}

			if rctx := chi.RouteContext(r.Context()); rctx != nil {
				for i, key := range rctx.URLParams.Keys {
					if key == "*" || i >= len(rctx.URLParams.Values) {
						continue
					}
					if v := rctx.URLParams.Values[i]; v != "" {
						attrs = append(attrs, slog.String("resource_name", v))
						break
					}
				}
			}

			if identity := oidc.UserIdentityFromContext(r.Context()); identity != nil {
				attrs = append(attrs,
					slog.String("user_name", identity.DisplayName),
					slog.String("user_role", identity.Role),
				)
			}

			logger.LogAttrs(r.Context(), slog.LevelInfo, "audit", attrs...)
		})
	}
}

// statusRecorder wraps http.ResponseWriter to capture the response status code.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.statusCode = code
	sr.ResponseWriter.WriteHeader(code)
}

// resourceTypeFromPath extracts the resource type from a REST URL path.
// It takes the first path segment after "/api/" and singularizes simple names
// (e.g. "/api/topics/foo" → "topic", "/api/kafka-connect/..." → "kafka-connect").
func resourceTypeFromPath(path string) string {
	const prefix = "/api/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	p := path[len(prefix):]
	if i := strings.Index(p, "/"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return ""
	}
	// Singularize simple (non-hyphenated) plural names.
	if !strings.Contains(p, "-") {
		p = strings.TrimSuffix(p, "s")
	}
	return p
}

// actionFromMethod maps an HTTP method to an uppercase audit action label.
func actionFromMethod(method string) string {
	switch method {
	case http.MethodPost:
		return "CREATE"
	case http.MethodPut, http.MethodPatch:
		return "UPDATE"
	case http.MethodDelete:
		return "DELETE"
	default:
		return strings.ToUpper(method)
	}
}

// ensurePrefixFormat ensures that the given path starts and ends with a slash
func ensurePrefixFormat(path string) string {
	isRootPath := len(path) == 1 && path[0] == '/'
	if path == "" || isRootPath {
		return ""
	}

	// add leading slash
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// add trailing slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	return path
}

// Creates a middleware that adds the build timestamp as a header to each response.
// The frontend uses this object to detect if the backend server has been updated,
// and therefore knows when the Single Page Application should be reloaded as well.
func createSetVersionInfoHeader(builtAt string) func(next http.Handler) http.Handler {
	buildTimestamp := time.Now()
	// Try to parse given string from ldflags as a timestamp
	if timestampInt, err := strconv.Atoi(builtAt); err == nil {
		buildTimestamp = time.Unix(int64(timestampInt), 0)
	}

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("app-build-timestamp", strconv.Itoa(int(buildTimestamp.Unix())))
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

// Create a middleware that sets HSTS headers when serving via TLS
func createHSTSHeaderMiddleware(tlsEnabled bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tlsEnabled {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// forceLoopbackMiddleware blocks requests not coming from the loopback interface.
func forceLoopbackMiddleware(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
			if !ok {
				logger.InfoContext(r.Context(), "request does not contain interface binding information")
				rest.HandleNotFound(logger).ServeHTTP(w, r)
				return
			}
			if !addr.IP.IsLoopback() {
				logger.InfoContext(r.Context(), "blocking request not directed to the loopback interface")
				rest.HandleNotFound(logger).ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
