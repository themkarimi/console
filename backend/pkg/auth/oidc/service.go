// Copyright 2024 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

// Package oidc provides OIDC/OAuth2 authentication helpers for Redpanda Console.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/redpanda-data/console/backend/pkg/config"
)

// UserIdentity holds the authenticated user's identity and the role derived
// from the configured RoleBindings.
type UserIdentity struct {
	// Subject is the OIDC subject identifier (stable unique user ID).
	Subject string
	// DisplayName is the human-readable name taken from the configured
	// UsernameClaim (or "email" as fallback).
	DisplayName string
	// AvatarURL is the user's profile picture URL (may be empty).
	AvatarURL string
	// Groups is the list of groups from the OIDC token's group claim.
	Groups []string
	// Role is the Console role derived from the user's groups via
	// RoleBindings ("admin", "editor", "viewer", or "").
	Role string
	// ResourcePermissions contains the fine-grained resource-level permissions
	// resolved for this user from the configured PermissionBindings.
	ResourcePermissions []config.ResourcePermission
}

// permissionOrder maps each permission level to a numeric rank so that
// higher levels can be compared as covering lower ones.
var permissionOrder = map[config.ResourcePermissionLevel]int{
	config.ResourcePermissionLevelRead:  1,
	config.ResourcePermissionLevelWrite: 2,
	config.ResourcePermissionLevelAdmin: 3,
}

// CanAccessResource reports whether the user has at least the required
// permission level on a resource of the specified type and name.
//
// The check uses the user's ResourcePermissions: any entry whose ResourceType
// matches, whose Pattern (treated as a full-match regex anchored to ^ and $)
// matches resourceName, and whose Permission level is sufficient causes the
// method to return true.
//
// If the user has no ResourcePermissions configured (ResourcePermissions is
// empty), true is returned unconditionally to preserve backward-compatible
// behaviour for deployments that rely solely on the global role.
func (u *UserIdentity) CanAccessResource(resourceType config.ResourceType, resourceName string, required config.ResourcePermissionLevel) bool {
	if len(u.ResourcePermissions) == 0 {
		return true
	}
	for _, rp := range u.ResourcePermissions {
		if rp.ResourceType != resourceType {
			continue
		}
		matched, err := regexp.MatchString("^(?:"+rp.Pattern+")$", resourceName)
		if err != nil {
			// Patterns are validated at config load time so this should be
			// unreachable in practice. Log and skip to aid debugging.
			slog.Warn("CanAccessResource: skipping invalid regex pattern",
				slog.String("pattern", rp.Pattern),
				slog.Any("error", err))
			continue
		}
		if !matched {
			continue
		}
		if permissionCovers(rp.Permission, required) {
			return true
		}
	}
	return false
}

// permissionCovers reports whether the granted level is sufficient for the
// required level.  The order is: read < write < admin.
func permissionCovers(granted, required config.ResourcePermissionLevel) bool {
	return permissionOrder[granted] >= permissionOrder[required]
}

// Service handles OIDC provider discovery, OAuth2 flows, and token validation.
type Service struct {
	cfg      config.OIDCConfig
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth2   oauth2.Config
}

// NewService creates a new OIDC Service.  It immediately contacts the OIDC
// provider's discovery endpoint to retrieve the provider metadata, so the
// caller should use a context with an appropriate deadline.
func NewService(ctx context.Context, cfg config.OIDCConfig) (*Service, error) {
	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider at %q: %w", cfg.IssuerURL, err)
	}

	scopes := deduplicateScopes(cfg.Scopes)

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&gooidc.Config{
		ClientID: cfg.ClientID,
	})

	return &Service{
		cfg:      cfg,
		provider: provider,
		verifier: verifier,
		oauth2:   oauth2Cfg,
	}, nil
}

// AuthCodeURL returns the URL to redirect the user to in order to start the
// OIDC authorization code flow.  state must be a CSRF-safe random string.
func (s *Service) AuthCodeURL(state string) string {
	return s.oauth2.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// ExchangeCode exchanges an authorization code (received in the callback) for
// an ID token and returns the validated UserIdentity.
func (s *Service) ExchangeCode(ctx context.Context, code string) (*UserIdentity, error) {
	token, err := s.oauth2.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("OIDC provider did not return an id_token")
	}

	return s.VerifyIDToken(ctx, rawIDToken)
}

// VerifyIDToken validates the given raw ID token string and returns the
// corresponding UserIdentity.
func (s *Service) VerifyIDToken(ctx context.Context, rawIDToken string) (*UserIdentity, error) {
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("ID token verification failed: %w", err)
	}

	if idToken.Expiry.Before(time.Now()) {
		return nil, errors.New("ID token has expired")
	}

	var claims map[string]json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	identity := &UserIdentity{
		Subject: idToken.Subject,
	}

	// Extract display name from configured username claim, then fall back.
	identity.DisplayName = extractStringClaim(claims, s.cfg.UsernameClaim)
	if identity.DisplayName == "" {
		identity.DisplayName = extractStringClaim(claims, "name")
	}
	if identity.DisplayName == "" {
		identity.DisplayName = extractStringClaim(claims, "email")
	}
	if identity.DisplayName == "" {
		identity.DisplayName = idToken.Subject
	}

	// Optional avatar claim.
	if s.cfg.AvatarClaimKey != "" {
		identity.AvatarURL = extractStringClaim(claims, s.cfg.AvatarClaimKey)
	}

	// Extract groups.
	identity.Groups = extractStringArrayClaim(claims, s.cfg.GroupClaimKey)

	// Derive role.
	identity.Role = s.resolveRole(identity.Groups)

	// Derive resource-level permissions.
	identity.ResourcePermissions = s.ResolveResourcePermissions(identity.Groups)

	return identity, nil
}

// resolveRole returns the first matching role from the configured role
// bindings, or the DefaultRole if no binding matches.
func (s *Service) resolveRole(groups []string) string {
	groupSet := make(map[string]bool, len(groups))
	for _, g := range groups {
		groupSet[g] = true
	}

	for _, rb := range s.cfg.RoleBindings {
		for _, g := range rb.Groups {
			if groupSet[g] {
				return rb.RoleName
			}
		}
	}
	return s.cfg.DefaultRole
}

// ResolveResourcePermissions returns all resource permissions granted to the
// user based on their group memberships and the configured PermissionBindings.
// Duplicate permissions (same ResourceType, Pattern, and Permission) are
// deduplicated.
func (s *Service) ResolveResourcePermissions(groups []string) []config.ResourcePermission {
	if len(s.cfg.PermissionBindings) == 0 {
		return nil
	}

	groupSet := make(map[string]bool, len(groups))
	for _, g := range groups {
		groupSet[g] = true
	}

	type permKey struct {
		resourceType config.ResourceType
		pattern      string
		permission   config.ResourcePermissionLevel
	}
	seen := make(map[permKey]bool)
	var perms []config.ResourcePermission

	for _, pb := range s.cfg.PermissionBindings {
		matched := false
		for _, g := range pb.Groups {
			if groupSet[g] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, rp := range pb.Permissions {
			k := permKey{rp.ResourceType, rp.Pattern, rp.Permission}
			if !seen[k] {
				seen[k] = true
				perms = append(perms, rp)
			}
		}
	}
	return perms
}

// IsUserAllowed returns true if the user's groups satisfy the AllowedGroups
// constraint (or AllowedGroups is empty, meaning all users are allowed).
func (s *Service) IsUserAllowed(groups []string) bool {
	if len(s.cfg.AllowedGroups) == 0 {
		return true
	}
	for _, allowed := range s.cfg.AllowedGroups {
		for _, g := range groups {
			if g == allowed {
				return true
			}
		}
	}
	return false
}

// deduplicateScopes ensures "openid" is always present and deduplicates.
func deduplicateScopes(scopes []string) []string {
	seen := map[string]bool{"openid": true}
	out := []string{"openid"}
	for _, s := range scopes {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// extractStringClaim reads a string value from the claims map.
func extractStringClaim(claims map[string]json.RawMessage, key string) string {
	raw, ok := claims[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// extractStringArrayClaim reads a []string value from the claims map.
func extractStringArrayClaim(claims map[string]json.RawMessage, key string) []string {
	raw, ok := claims[key]
	if !ok {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		// Some providers encode a single group as a bare string.
		var s string
		if err2 := json.Unmarshal(raw, &s); err2 == nil && s != "" {
			return []string{s}
		}
		return nil
	}
	return arr
}
