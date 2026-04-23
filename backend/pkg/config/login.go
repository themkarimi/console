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
	"fmt"
	"regexp"
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

	// PermissionBindings maps OIDC groups to fine-grained resource permissions
	// using regex patterns.  These supplement the global role assigned via
	// RoleBindings, allowing specific groups to access only the topics or
	// consumer groups whose names match the configured patterns.
	PermissionBindings []PermissionBinding `yaml:"permissionBindings"`

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

// ResourceType identifies the kind of resource a permission applies to.
type ResourceType string

const (
	// ResourceTypeTopic grants permissions on Kafka topics.
	ResourceTypeTopic ResourceType = "topic"
	// ResourceTypeConsumerGroup grants permissions on Kafka consumer groups.
	ResourceTypeConsumerGroup ResourceType = "consumerGroup"
)

// ResourcePermissionLevel defines the level of access granted on a resource.
type ResourcePermissionLevel string

const (
	// ResourcePermissionLevelRead grants read-only access to matching resources.
	ResourcePermissionLevelRead ResourcePermissionLevel = "read"
	// ResourcePermissionLevelWrite grants read and write access to matching resources.
	ResourcePermissionLevelWrite ResourcePermissionLevel = "write"
	// ResourcePermissionLevelAdmin grants full admin access to matching resources.
	ResourcePermissionLevelAdmin ResourcePermissionLevel = "admin"
)

// ResourcePermission grants a specific permission level on resources whose
// names match a given regex pattern.
type ResourcePermission struct {
	// ResourceType is the kind of resource this permission applies to
	// (e.g. "topic", "consumerGroup").
	ResourceType ResourceType `yaml:"resourceType"`
	// Pattern is a regular expression matched against resource names.
	Pattern string `yaml:"pattern"`
	// Permission is the access level granted: "read", "write", or "admin".
	Permission ResourcePermissionLevel `yaml:"permission"`
}

// PermissionBinding maps a set of OIDC groups to fine-grained resource
// permissions using regex patterns.  Users who belong to any of the listed
// groups receive all the listed ResourcePermissions.
type PermissionBinding struct {
	// Groups is the list of OIDC group names that receive these permissions.
	Groups []string `yaml:"groups"`
	// Permissions is the list of resource-level permissions to grant.
	Permissions []ResourcePermission `yaml:"permissions"`
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
	for i, pb := range c.PermissionBindings {
		if len(pb.Groups) == 0 {
			return fmt.Errorf("login.oidc.permissionBindings[%d] must have at least one group", i)
		}
		if len(pb.Permissions) == 0 {
			return fmt.Errorf("login.oidc.permissionBindings[%d] must have at least one permission", i)
		}
		for j, rp := range pb.Permissions {
			if rp.ResourceType != ResourceTypeTopic && rp.ResourceType != ResourceTypeConsumerGroup {
				return fmt.Errorf("login.oidc.permissionBindings[%d].permissions[%d]: unsupported resourceType %q, must be %q or %q",
					i, j, rp.ResourceType, ResourceTypeTopic, ResourceTypeConsumerGroup)
			}
			if rp.Pattern == "" {
				return fmt.Errorf("login.oidc.permissionBindings[%d].permissions[%d]: pattern must not be empty", i, j)
			}
			if _, err := regexp.Compile(rp.Pattern); err != nil {
				return fmt.Errorf("login.oidc.permissionBindings[%d].permissions[%d]: invalid regex pattern %q: %w", i, j, rp.Pattern, err)
			}
			if rp.Permission != ResourcePermissionLevelRead &&
				rp.Permission != ResourcePermissionLevelWrite &&
				rp.Permission != ResourcePermissionLevelAdmin {
				return fmt.Errorf("login.oidc.permissionBindings[%d].permissions[%d]: unsupported permission %q, must be %q, %q or %q",
					i, j, rp.Permission, ResourcePermissionLevelRead, ResourcePermissionLevelWrite, ResourcePermissionLevelAdmin)
			}
		}
	}
	return nil
}
