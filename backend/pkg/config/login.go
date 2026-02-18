// Copyright 2024 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package config

import (
	"errors"
	"flag"
)

// Login contains configuration for authenticating users who access Redpanda Console.
type Login struct {
	OIDC OIDCConfig `yaml:"oidc"`
}

// RegisterFlags registers sensitive login config values as CLI flags.
func (l *Login) RegisterFlags(f *flag.FlagSet) {
	l.OIDC.RegisterFlags(f)
}

// Validate the login config.
func (l *Login) Validate() error {
	if l.OIDC.Enabled {
		return l.OIDC.Validate()
	}
	return nil
}

// SetDefaults for the login config.
func (l *Login) SetDefaults() {
	l.OIDC.SetDefaults()
}

// OIDCConfig holds all configuration necessary to enable authentication via OIDC
// (e.g. Keycloak, Okta, Auth0, etc.) using the Authorization Code grant.
type OIDCConfig struct {
	// Enabled toggles OIDC authentication. When false, no login is required.
	Enabled bool `yaml:"enabled"`

	// IssuerURL is the base URL of the OIDC provider, e.g.
	// "https://keycloak.example.com/realms/myrealm".
	// The well-known discovery document is fetched from
	// {IssuerURL}/.well-known/openid-configuration.
	IssuerURL string `yaml:"issuerUrl"`

	// ClientID is the OAuth2 client ID registered in the OIDC provider.
	ClientID string `yaml:"clientId"`

	// ClientSecret is the OAuth2 client secret corresponding to ClientID.
	ClientSecret string `yaml:"clientSecret"`

	// RedirectURL is the URL the provider redirects to after successful
	// authentication, e.g. "https://console.example.com/auth/callback/oidc".
	RedirectURL string `yaml:"redirectUrl"`

	// Scopes specifies the OAuth2 / OIDC scopes to request.
	// "openid" is always included automatically.
	Scopes []string `yaml:"scopes"`

	// GroupClaimKey is the name of the ID-token JWT claim that contains the
	// user's group memberships (e.g. "groups").  The claim value must be a
	// JSON array of strings.
	GroupClaimKey string `yaml:"groupClaimKey"`

	// UsernameClaim is the claim used to derive the human-readable display
	// name, e.g. "preferred_username" or "name".
	UsernameClaim string `yaml:"usernameClaim"`

	// AvatarClaimKey is the claim that contains a URL to the user's avatar
	// image (optional).
	AvatarClaimKey string `yaml:"avatarClaimKey"`

	// AllowedGroups, when non-empty, restricts login to users who are a
	// member of at least one of the listed groups.  Leave empty to allow all
	// authenticated users.
	AllowedGroups []string `yaml:"allowedGroups"`

	// RoleBindings maps Console roles to OIDC group names.  The first
	// matching binding (in order) wins.  Supported role names: admin, editor,
	// viewer.  If a user has no matching binding they are denied access unless
	// a DefaultRole is set.
	RoleBindings []RoleBinding `yaml:"roleBindings"`

	// DefaultRole is the role assigned to users who do not match any
	// RoleBinding.  Leave empty to deny access to unmatched users.
	DefaultRole string `yaml:"defaultRole"`

	// SessionCookieName is the name of the HTTP cookie used to store the
	// session.  Defaults to "console_session".
	SessionCookieName string `yaml:"sessionCookieName"`

	// SessionCookieMaxAgeSecs is the maximum lifetime (in seconds) of the
	// session cookie.  Defaults to 86400 (24 h).
	SessionCookieMaxAgeSecs int `yaml:"sessionCookieMaxAgeSecs"`

	// CookieEncryptionSecret is a secret used to sign/encrypt the session
	// cookie.  Must be 32 or 64 bytes long. Both sizes use AES-256-GCM;
	// a 64-byte key is accepted for convenience (only the first 32 bytes
	// are used).
	// Required when OIDC is enabled.
	CookieEncryptionSecret string `yaml:"cookieEncryptionSecret"`

	// SessionCookieSecure controls whether the Secure attribute is set on the
	// session cookie.  Set to true when Console is served over HTTPS (recommended
	// for production).  Defaults to false to allow HTTP development setups.
	SessionCookieSecure bool `yaml:"sessionCookieSecure"`
}

// RoleBinding maps a Console role name to a list of OIDC group names.
type RoleBinding struct {
	// RoleName is one of: "admin", "editor", "viewer".
	RoleName string `yaml:"roleName"`
	// Groups is the list of OIDC group names that are granted this role.
	Groups []string `yaml:"groups"`
}

// RegisterFlags registers sensitive OIDCConfig values as CLI flags.
func (c *OIDCConfig) RegisterFlags(f *flag.FlagSet) {
	f.StringVar(&c.ClientSecret, "login.oidc.clientSecret", "", "OIDC client secret")
	f.StringVar(&c.CookieEncryptionSecret, "login.oidc.cookieEncryptionSecret", "", "Secret used to sign session cookies")
}

// SetDefaults sets sensible defaults for OIDCConfig.
func (c *OIDCConfig) SetDefaults() {
	c.Scopes = []string{"openid", "profile", "email"}
	c.GroupClaimKey = "groups"
	c.UsernameClaim = "preferred_username"
	c.SessionCookieName = "console_session"
	c.SessionCookieMaxAgeSecs = 86400 // 24 h
}

// Validate the OIDC configuration.
func (c *OIDCConfig) Validate() error {
	if c.IssuerURL == "" {
		return errors.New("login.oidc.issuerUrl must be set when OIDC is enabled")
	}
	if c.ClientID == "" {
		return errors.New("login.oidc.clientId must be set when OIDC is enabled")
	}
	if c.ClientSecret == "" {
		return errors.New("login.oidc.clientSecret must be set when OIDC is enabled")
	}
	if c.RedirectURL == "" {
		return errors.New("login.oidc.redirectUrl must be set when OIDC is enabled")
	}
	if c.CookieEncryptionSecret == "" {
		return errors.New("login.oidc.cookieEncryptionSecret must be set when OIDC is enabled")
	}
	l := len(c.CookieEncryptionSecret)
	if l != 32 && l != 64 {
		return errors.New("login.oidc.cookieEncryptionSecret must be exactly 32 or 64 bytes")
	}
	for _, rb := range c.RoleBindings {
		if rb.RoleName == "" {
			return errors.New("each login.oidc.roleBindings entry must have a non-empty roleName")
		}
		if len(rb.Groups) == 0 {
			return errors.New("each login.oidc.roleBindings entry must have at least one group")
		}
	}
	return nil
}
