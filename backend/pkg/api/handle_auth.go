// Copyright 2024 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package api

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/redpanda-data/console/backend/pkg/auth/oidc"
)

const (
	// oidcStateLen is the length of the random CSRF state token in bytes.
	oidcStateLen = 32
	// stateCookieName is the name of the short-lived cookie used to carry the
	// CSRF state parameter across the OIDC redirect.
	stateCookieName = "console_oidc_state"
)

// handleOIDCLogin redirects the user's browser to the configured OIDC
// provider to begin the Authorization Code flow.
func (api *API) handleOIDCLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := generateState()
		if err != nil {
			api.Logger.ErrorContext(r.Context(), "failed to generate OIDC state", slog.Any("error", err))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Store state in a short-lived cookie so we can verify it on callback.
		http.SetCookie(w, &http.Cookie{
			Name:     stateCookieName,
			Value:    state,
			Path:     "/auth/callback/oidc",
			MaxAge:   300, // 5 minutes
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   api.Cfg.Login.OIDC.SessionCookieSecure,
		})

		authURL := api.OIDCService.AuthCodeURL(state)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// handleOIDCCallback processes the redirect from the OIDC provider, exchanges
// the authorization code for tokens, validates them, and establishes a session.
func (api *API) handleOIDCCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Verify CSRF state.
		stateCookie, err := r.Cookie(stateCookieName)
		if err != nil || stateCookie.Value == "" {
			api.Logger.WarnContext(ctx, "OIDC callback missing state cookie")
			redirectWithError(w, r, "token_exchange_failed")
			return
		}
		// Clear the state cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     stateCookieName,
			Value:    "",
			Path:     "/auth/callback/oidc",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   api.Cfg.Login.OIDC.SessionCookieSecure,
		})

		queryState := r.URL.Query().Get("state")
		if queryState == "" || queryState != stateCookie.Value {
			api.Logger.WarnContext(ctx, "OIDC callback state mismatch",
				slog.String("expected", stateCookie.Value),
				slog.String("got", queryState))
			redirectWithError(w, r, "token_exchange_failed")
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			api.Logger.WarnContext(ctx, "OIDC callback missing code parameter")
			redirectWithError(w, r, "token_exchange_failed")
			return
		}

		identity, err := api.OIDCService.ExchangeCode(ctx, code)
		if err != nil {
			api.Logger.ErrorContext(ctx, "OIDC token exchange failed", slog.Any("error", err))
			redirectWithError(w, r, "token_exchange_failed")
			return
		}

		// Check AllowedGroups constraint.
		if !api.OIDCService.IsUserAllowed(identity.Groups) {
			api.Logger.WarnContext(ctx, "OIDC user not in AllowedGroups",
				slog.String("subject", identity.Subject))
			u := url.Values{}
			u.Set("error_code", "permission_denied")
			u.Set("oidc_subject", identity.Subject)
			http.Redirect(w, r, "/login?"+u.Encode(), http.StatusFound)
			return
		}

		// Check that a role was resolved.
		if identity.Role == "" {
			api.Logger.WarnContext(ctx, "OIDC user has no matching role binding",
				slog.String("subject", identity.Subject))
			u := url.Values{}
			u.Set("error_code", "permission_denied")
			u.Set("oidc_subject", identity.Subject)
			http.Redirect(w, r, "/login?"+u.Encode(), http.StatusFound)
			return
		}

		if err := api.SessionManager.SetSession(w, identity); err != nil {
			api.Logger.ErrorContext(ctx, "failed to set session cookie", slog.Any("error", err))
			redirectWithError(w, r, "console_internal")
			return
		}

		api.Logger.InfoContext(ctx, "OIDC login successful",
			slog.String("subject", identity.Subject),
			slog.String("role", identity.Role))

		http.Redirect(w, r, "/overview", http.StatusFound)
	}
}

// handleOIDCLogout clears the session cookie and redirects to the login page.
func (api *API) handleOIDCLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api.SessionManager.ClearSession(w)
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// generateState produces a cryptographically random CSRF state token.
func generateState() (string, error) {
	b := make([]byte, oidcStateLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// redirectWithError redirects to the login page with the given error_code
// query parameter.
func redirectWithError(w http.ResponseWriter, r *http.Request, code string) {
	u := url.Values{}
	u.Set("error_code", code)
	http.Redirect(w, r, "/login?"+u.Encode(), http.StatusFound)
}

// sessionInjectMiddleware is an HTTP middleware that reads the session cookie,
// decrypts it, and – if valid – injects the UserIdentity into the request
// context.  It never rejects requests; call requireAuthMiddleware after this
// to enforce authentication.
func (api *API) sessionInjectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := api.SessionManager.GetSession(r)
		if err == nil {
			identity := &oidc.UserIdentity{
				Subject:     session.Subject,
				DisplayName: session.DisplayName,
				AvatarURL:   session.AvatarURL,
				Groups:      session.Groups,
				Role:        session.Role,
			}
			// Recompute resource-level permissions from the stored groups so
			// that any config changes take effect without requiring a new login.
			if api.OIDCService != nil {
				identity.ResourcePermissions = api.OIDCService.ResolveResourcePermissions(session.Groups)
			}
			r = r.WithContext(oidc.WithUserIdentity(r.Context(), identity))
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuthMiddleware rejects requests that do not carry a user identity
// in their context (i.e. requests that were not authenticated by
// sessionInjectMiddleware).  Paths listed in noAuthPaths are always allowed
// through regardless of session state.
func requireAuthMiddleware(noAuthPaths []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			for _, p := range noAuthPaths {
				if strings.HasPrefix(path, p) {
					next.ServeHTTP(w, r)
					return
				}
			}

			if oidc.UserIdentityFromContext(r.Context()) == nil {
				http.Error(w, "unauthorized: no valid session", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

