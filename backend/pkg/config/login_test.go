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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validOIDCConfig() OIDCConfig {
	return OIDCConfig{
		Enabled:                true,
		IssuerURL:              "https://keycloak.example.com/realms/myrealm",
		ClientID:               "console",
		ClientSecret:           "s3cr3t",
		RedirectURL:            "https://console.example.com/auth/callback/oidc",
		CookieEncryptionSecret: "12345678901234567890123456789012", // 32 bytes
	}
}

func TestOIDCConfig_Validate_Valid(t *testing.T) {
	cfg := validOIDCConfig()
	assert.NoError(t, cfg.Validate())
}

func TestOIDCConfig_Validate_MissingIssuerURL(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.IssuerURL = ""
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuerUrl")
}

func TestOIDCConfig_Validate_MissingClientID(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.ClientID = ""
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clientId")
}

func TestOIDCConfig_Validate_MissingClientSecret(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.ClientSecret = ""
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clientSecret")
}

func TestOIDCConfig_Validate_MissingRedirectURL(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.RedirectURL = ""
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirectUrl")
}

func TestOIDCConfig_Validate_MissingCookieEncryptionSecret(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.CookieEncryptionSecret = ""
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cookieEncryptionSecret")
}

func TestOIDCConfig_Validate_InvalidCookieSecretLength(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.CookieEncryptionSecret = "tooshort"
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 or 64")
}

func TestOIDCConfig_Validate_64ByteSecretIsValid(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.CookieEncryptionSecret = "1234567890123456789012345678901234567890123456789012345678901234" // 64 bytes
	assert.NoError(t, cfg.Validate())
}

func TestOIDCConfig_Validate_RoleBindingMissingRoleName(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.RoleBindings = []RoleBinding{
		{RoleName: "", Groups: []string{"admins"}},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roleName")
}

func TestOIDCConfig_Validate_RoleBindingMissingGroups(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.RoleBindings = []RoleBinding{
		{RoleName: "admin", Groups: nil},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group")
}

func TestLogin_Validate_DisabledSkipsOIDCValidation(t *testing.T) {
	l := Login{
		OIDC: OIDCConfig{
			Enabled: false,
			// fields intentionally invalid – should be skipped
			IssuerURL: "",
		},
	}
	assert.NoError(t, l.Validate())
}

func TestOIDCConfig_SetDefaults(t *testing.T) {
	var cfg OIDCConfig
	cfg.SetDefaults()
	assert.Contains(t, cfg.Scopes, "openid")
	assert.Equal(t, "groups", cfg.GroupClaimKey)
	assert.Equal(t, "preferred_username", cfg.UsernameClaim)
	assert.Equal(t, "console_session", cfg.SessionCookieName)
	assert.Equal(t, 86400, cfg.SessionCookieMaxAgeSecs)
}

func TestOIDCConfig_Validate_PermissionBindingMissingGroups(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.PermissionBindings = []PermissionBinding{
		{Groups: nil, Permissions: []ResourcePermission{
			{ResourceType: ResourceTypeTopic, Pattern: "a.*", Permission: ResourcePermissionLevelRead},
		}},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group")
}

func TestOIDCConfig_Validate_PermissionBindingMissingPermissions(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.PermissionBindings = []PermissionBinding{
		{Groups: []string{"group-a"}, Permissions: nil},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission")
}

func TestOIDCConfig_Validate_PermissionBindingInvalidResourceType(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.PermissionBindings = []PermissionBinding{
		{Groups: []string{"group-a"}, Permissions: []ResourcePermission{
			{ResourceType: "unknownType", Pattern: "a.*", Permission: ResourcePermissionLevelRead},
		}},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resourceType")
}

func TestOIDCConfig_Validate_PermissionBindingEmptyPattern(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.PermissionBindings = []PermissionBinding{
		{Groups: []string{"group-a"}, Permissions: []ResourcePermission{
			{ResourceType: ResourceTypeTopic, Pattern: "", Permission: ResourcePermissionLevelRead},
		}},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

func TestOIDCConfig_Validate_PermissionBindingInvalidRegex(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.PermissionBindings = []PermissionBinding{
		{Groups: []string{"group-a"}, Permissions: []ResourcePermission{
			{ResourceType: ResourceTypeTopic, Pattern: "[invalid", Permission: ResourcePermissionLevelRead},
		}},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regex pattern")
}

func TestOIDCConfig_Validate_PermissionBindingInvalidPermissionLevel(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.PermissionBindings = []PermissionBinding{
		{Groups: []string{"group-a"}, Permissions: []ResourcePermission{
			{ResourceType: ResourceTypeTopic, Pattern: "a.*", Permission: "superuser"},
		}},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission")
}

func TestOIDCConfig_Validate_PermissionBindingValid(t *testing.T) {
	cfg := validOIDCConfig()
	cfg.PermissionBindings = []PermissionBinding{
		{Groups: []string{"group-a"}, Permissions: []ResourcePermission{
			{ResourceType: ResourceTypeTopic, Pattern: `a\..*`, Permission: ResourcePermissionLevelRead},
			{ResourceType: ResourceTypeConsumerGroup, Pattern: `cg-.*`, Permission: ResourcePermissionLevelWrite},
		}},
	}
	assert.NoError(t, cfg.Validate())
}
