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
