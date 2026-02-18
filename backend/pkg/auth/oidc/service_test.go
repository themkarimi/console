// Copyright 2024 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redpanda-data/console/backend/pkg/config"
)

// ---- resolveRole tests ----

func TestService_resolveRole(t *testing.T) {
	tests := []struct {
		name         string
		roleBindings []config.RoleBinding
		defaultRole  string
		groups       []string
		wantRole     string
	}{
		{
			name: "admin via first binding",
			roleBindings: []config.RoleBinding{
				{RoleName: "admin", Groups: []string{"console-admins"}},
				{RoleName: "editor", Groups: []string{"console-editors"}},
				{RoleName: "viewer", Groups: []string{"console-viewers"}},
			},
			groups:   []string{"console-admins"},
			wantRole: "admin",
		},
		{
			name: "editor matched",
			roleBindings: []config.RoleBinding{
				{RoleName: "admin", Groups: []string{"console-admins"}},
				{RoleName: "editor", Groups: []string{"console-editors"}},
			},
			groups:   []string{"console-editors"},
			wantRole: "editor",
		},
		{
			name: "first match wins when user belongs to multiple groups",
			roleBindings: []config.RoleBinding{
				{RoleName: "admin", Groups: []string{"console-admins"}},
				{RoleName: "editor", Groups: []string{"console-editors"}},
			},
			groups:   []string{"console-editors", "console-admins"},
			wantRole: "admin",
		},
		{
			name: "no matching binding returns default role",
			roleBindings: []config.RoleBinding{
				{RoleName: "admin", Groups: []string{"console-admins"}},
			},
			defaultRole: "viewer",
			groups:      []string{"some-other-group"},
			wantRole:    "viewer",
		},
		{
			name:         "empty bindings and no default returns empty role",
			roleBindings: nil,
			groups:       []string{"any-group"},
			wantRole:     "",
		},
		{
			name: "no groups returns default role",
			roleBindings: []config.RoleBinding{
				{RoleName: "admin", Groups: []string{"console-admins"}},
			},
			defaultRole: "viewer",
			groups:      nil,
			wantRole:    "viewer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{
				cfg: config.OIDCConfig{
					RoleBindings: tt.roleBindings,
					DefaultRole:  tt.defaultRole,
				},
			}
			got := svc.resolveRole(tt.groups)
			assert.Equal(t, tt.wantRole, got)
		})
	}
}

// ---- IsUserAllowed tests ----

func TestService_IsUserAllowed(t *testing.T) {
	tests := []struct {
		name          string
		allowedGroups []string
		userGroups    []string
		wantAllowed   bool
	}{
		{
			name:          "empty allowed groups allows everyone",
			allowedGroups: nil,
			userGroups:    []string{"anything"},
			wantAllowed:   true,
		},
		{
			name:          "user in allowed group",
			allowedGroups: []string{"console-users"},
			userGroups:    []string{"console-users", "other-group"},
			wantAllowed:   true,
		},
		{
			name:          "user not in allowed group",
			allowedGroups: []string{"console-users"},
			userGroups:    []string{"other-group"},
			wantAllowed:   false,
		},
		{
			name:          "user with no groups not allowed",
			allowedGroups: []string{"console-users"},
			userGroups:    nil,
			wantAllowed:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{cfg: config.OIDCConfig{AllowedGroups: tt.allowedGroups}}
			got := svc.IsUserAllowed(tt.userGroups)
			assert.Equal(t, tt.wantAllowed, got)
		})
	}
}

// ---- extractStringClaim / extractStringArrayClaim tests ----

func TestExtractStringClaim(t *testing.T) {
	claims := map[string]json.RawMessage{
		"name":  json.RawMessage(`"Alice"`),
		"count": json.RawMessage(`42`),
	}
	assert.Equal(t, "Alice", extractStringClaim(claims, "name"))
	assert.Equal(t, "", extractStringClaim(claims, "missing"))
	assert.Equal(t, "", extractStringClaim(claims, "count"))
}

func TestExtractStringArrayClaim(t *testing.T) {
	claims := map[string]json.RawMessage{
		"groups":       json.RawMessage(`["admin","editor"]`),
		"single_group": json.RawMessage(`"admin"`),
		"not_strings":  json.RawMessage(`[1,2,3]`),
	}
	assert.Equal(t, []string{"admin", "editor"}, extractStringArrayClaim(claims, "groups"))
	assert.Equal(t, []string{"admin"}, extractStringArrayClaim(claims, "single_group"))
	assert.Nil(t, extractStringArrayClaim(claims, "missing"))
	assert.Nil(t, extractStringArrayClaim(claims, "not_strings"))
}

// ---- SessionManager tests ----

func newTestSessionManager(t *testing.T) *SessionManager {
	t.Helper()
	// 32 ASCII bytes
	key := "12345678901234567890123456789012"
	sm, err := NewSessionManager("test_session", 3600, key, false)
	require.NoError(t, err)
	return sm
}

func TestSessionManager_RoundTrip(t *testing.T) {
	sm := newTestSessionManager(t)

	identity := &UserIdentity{
		Subject:     "user123",
		DisplayName: "Alice",
		AvatarURL:   "https://example.com/avatar.png",
		Groups:      []string{"console-admins"},
		Role:        "admin",
	}

	// Write session cookie.
	rec := httptest.NewRecorder()
	require.NoError(t, sm.SetSession(rec, identity))

	// Build a request carrying the cookie.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	// Read session back.
	got, err := sm.GetSession(req)
	require.NoError(t, err)
	assert.Equal(t, identity.Subject, got.Subject)
	assert.Equal(t, identity.DisplayName, got.DisplayName)
	assert.Equal(t, identity.AvatarURL, got.AvatarURL)
	assert.Equal(t, identity.Groups, got.Groups)
	assert.Equal(t, identity.Role, got.Role)
	assert.WithinDuration(t, time.Now().Add(3600*time.Second), got.ExpiresAt, 5*time.Second)
}

func TestSessionManager_MissingCookie(t *testing.T) {
	sm := newTestSessionManager(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := sm.GetSession(req)
	assert.Error(t, err)
}

func TestSessionManager_TamperedCookie(t *testing.T) {
	sm := newTestSessionManager(t)

	identity := &UserIdentity{Subject: "u1", Role: "viewer"}
	rec := httptest.NewRecorder()
	require.NoError(t, sm.SetSession(rec, identity))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		// Flip a byte in the cookie value to simulate tampering.
		tampered := c
		tampered.Value = c.Value + "XX"
		req.AddCookie(tampered)
	}

	_, err := sm.GetSession(req)
	assert.Error(t, err)
}

func TestSessionManager_ClearSession(t *testing.T) {
	sm := newTestSessionManager(t)
	rec := httptest.NewRecorder()
	sm.ClearSession(rec)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "test_session", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

func TestNewSessionManager_InvalidKeyLength(t *testing.T) {
	_, err := NewSessionManager("s", 3600, "tooshort", false)
	assert.Error(t, err)
}

// ---- context helper tests ----

func TestUserIdentityContext(t *testing.T) {
	identity := &UserIdentity{Subject: "sub1", Role: "admin"}

	ctx := WithUserIdentity(t.Context(), identity)
	got := UserIdentityFromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, "sub1", got.Subject)
	assert.Equal(t, "admin", got.Role)
}

func TestUserIdentityContext_Missing(t *testing.T) {
	got := UserIdentityFromContext(t.Context())
	assert.Nil(t, got)
}

// ---- deduplicateScopes tests ----

func TestDeduplicateScopes(t *testing.T) {
	got := deduplicateScopes([]string{"openid", "profile", "openid", "email", "profile"})
	assert.Equal(t, []string{"openid", "profile", "email"}, got)
}

func TestDeduplicateScopes_AddsOpenID(t *testing.T) {
	got := deduplicateScopes([]string{"profile"})
	assert.Equal(t, []string{"openid", "profile"}, got)
}
