---
title: OIDC Authentication & Authorization
path: /docs/features/authentication
---

# OIDC Authentication & Authorization

Redpanda Console supports single sign-on (SSO) via **OpenID Connect (OIDC)** using the Authorization Code grant flow. When OIDC is enabled, users are redirected to your identity provider (IdP) to log in; after a successful login the IdP issues an ID token that Console validates, extracts identity claims from, and maps to a Console role.

> **Enterprise feature** — OIDC SSO and role-based access control (RBAC) require a valid Redpanda enterprise license. Set `licenseFilepath` or the `license` key in your configuration before enabling OIDC.

## How it works

1. The user visits Console and is redirected to the IdP's authorization endpoint.
2. The IdP authenticates the user and redirects back to Console with an authorization code.
3. Console exchanges the code for an ID token, verifies its signature against the IdP's JWKS, and extracts claims.
4. Console maps the user's groups (from the configured `groupClaimKey` claim) to a Console role via `roleBindings`.
5. Console creates an encrypted session cookie and the user is logged in.

## Configuration

All OIDC settings live under the `login.oidc` key in your YAML config file.

### Minimal configuration

```yaml
login:
  oidc:
    enabled: true
    issuerUrl: "https://accounts.example.com"
    clientId: "console"
    # clientSecret: set via flag or environment variable (see below)
    redirectUrl: "https://console.example.com/login/callbacks/oidc"
    # cookieEncryptionSecret: set via flag or environment variable (see below)
    sessionCookieSecure: true  # recommended in production (requires HTTPS)
    roleBindings:
      - roleName: admin
        groups: ["platform-admins"]
      - roleName: viewer
        groups: ["developers"]
```

### Full configuration reference

```yaml
login:
  oidc:
    # Enable or disable OIDC. When false, no authentication is enforced.
    enabled: true

    # Base URL of the OIDC provider. Console fetches
    # {issuerUrl}/.well-known/openid-configuration on startup.
    issuerUrl: "https://accounts.example.com"

    # OAuth2 client ID registered in the identity provider.
    clientId: "console"

    # OAuth2 client secret. Prefer setting this via the
    # --login.oidc.clientSecret flag or LOGIN_OIDC_CLIENTSECRET env variable.
    clientSecret: ""

    # Callback URL that the identity provider redirects to after login.
    # Must match the redirect URI configured in the identity provider.
    redirectUrl: "https://console.example.com/login/callbacks/oidc"

    # OAuth2/OIDC scopes to request. "openid" is always included.
    # Default: ["openid", "profile", "email"]
    scopes:
      - openid
      - profile
      - email

    # JWT claim that contains the user's group memberships.
    # The claim value must be a JSON array of strings.
    # Default: "groups"
    groupClaimKey: "groups"

    # JWT claim used as the display name in the Console UI.
    # Falls back to "name", then "email", then the subject if not found.
    # Default: "preferred_username"
    usernameClaim: "preferred_username"

    # Optional JWT claim containing a URL to the user's avatar image.
    avatarClaimKey: "picture"

    # When non-empty, only users who belong to at least one of these groups
    # may log in. Leave empty to allow all authenticated users.
    allowedGroups: []

    # Maps Console roles to lists of OIDC group names.
    # The first matching binding wins. Supported role names: admin, editor, viewer.
    roleBindings:
      - roleName: admin
        groups: ["platform-admins"]
      - roleName: editor
        groups: ["developers"]
      - roleName: viewer
        groups: ["read-only-users"]

    # Assigns fine-grained resource-level permissions to OIDC groups.
    # These supplement the global role from roleBindings.
    # Supported resourceType values: "topic", "consumerGroup"
    # Supported permission values: "read", "write", "admin"
    permissionBindings:
      - groups: ["topic-readers"]
        permissions:
          - resourceType: topic
            pattern: ".*"        # regular expression matched against topic names
            permission: read
      - groups: ["payments-team"]
        permissions:
          - resourceType: topic
            pattern: "^payments-.*"
            permission: write
          - resourceType: consumerGroup
            pattern: "^payments-.*"
            permission: read

    # Role assigned to authenticated users who do not match any roleBinding.
    # Leave empty to deny access to unmatched users.
    defaultRole: ""

    # Name of the session cookie. Default: "console_session"
    sessionCookieName: "console_session"

    # Session cookie lifetime in seconds. Default: 86400 (24 hours)
    sessionCookieMaxAgeSecs: 86400

    # Secret used to encrypt the session cookie with AES-256-GCM.
    # Must be exactly 32 or 64 bytes. Prefer setting this via the
    # --login.oidc.cookieEncryptionSecret flag or the
    # LOGIN_OIDC_COOKIEENCRYPTIONSECRET env variable.
    cookieEncryptionSecret: ""

    # Set the Secure attribute on the session cookie.
    # Enable this when Console is served over HTTPS (recommended for production).
    # Default: false
    sessionCookieSecure: false
```

### Setting secrets securely

The `clientSecret` and `cookieEncryptionSecret` values are sensitive. Avoid placing them in your YAML config file. Instead, use one of the following options:

**CLI flags** (useful for Docker and Kubernetes):

```bash
console \
  --config.filepath=/etc/console/console.yaml \
  --login.oidc.clientSecret="$OIDC_CLIENT_SECRET" \
  --login.oidc.cookieEncryptionSecret="$COOKIE_SECRET"
```

**Environment variables**:

```bash
export LOGIN_OIDC_CLIENTSECRET="your-client-secret"
export LOGIN_OIDC_COOKIEENCRYPTIONSECRET="your-32-or-64-byte-secret"
```

> **Generating a cookie encryption secret**: Run `openssl rand -hex 16` to generate a random 32-byte hex string suitable for use as `cookieEncryptionSecret`.

## Authorization

### Roles

Console defines three built-in roles in order of increasing privilege:

| Role     | Description                                                     |
|----------|-----------------------------------------------------------------|
| `viewer` | Read-only access to all resources                               |
| `editor` | Read and write access to most resources                         |
| `admin`  | Full access including destructive operations and configuration  |

Roles are assigned to users through `roleBindings`. The first binding whose `groups` list contains one of the user's OIDC groups is used. Users who do not match any binding receive the `defaultRole` (if set) or are denied access.

### Fine-grained permissions

`permissionBindings` let you restrict which specific topics or consumer groups a group can access, independently of their global role. A user with `permissionBindings` configured must pass **both** the role check and the resource-level permission check to access a resource.

If no `permissionBindings` are configured for a user, their global role applies to all resources (backwards-compatible behaviour).

Permission levels follow a hierarchy: `read` < `write` < `admin`. A higher level covers all lower levels.

## Provider-specific examples

### Keycloak

1. Create a new **confidential** OpenID Connect client in your Keycloak realm.
2. Set the **Valid Redirect URIs** to `https://console.example.com/login/callbacks/oidc`.
3. Enable the **groups** client scope or add a mapper that adds group memberships to the ID token as a claim named `groups`.
4. Note the **Client ID** and **Client Secret** from the Credentials tab.

```yaml
login:
  oidc:
    enabled: true
    issuerUrl: "https://keycloak.example.com/realms/myrealm"
    clientId: "console"
    redirectUrl: "https://console.example.com/login/callbacks/oidc"
    groupClaimKey: "groups"
    roleBindings:
      - roleName: admin
        groups: ["/admin-group"]  # Keycloak prefixes group paths with /
```

### Okta

1. Create a new **Web** OIDC application in Okta.
2. Set the **Sign-in redirect URI** to `https://console.example.com/login/callbacks/oidc`.
3. Add a **Groups claim** to the ID token in the application's Sign On policy or via an authorization server claim rule.
4. Note the **Client ID**, **Client Secret**, and the **Okta domain**.

```yaml
login:
  oidc:
    enabled: true
    issuerUrl: "https://dev-12345678.okta.com"
    clientId: "0oa..."
    redirectUrl: "https://console.example.com/login/callbacks/oidc"
    groupClaimKey: "groups"
    roleBindings:
      - roleName: admin
        groups: ["Console Admins"]
```

### Google Workspace

1. Create an **OAuth 2.0 Client ID** of type **Web application** in Google Cloud Console.
2. Add `https://console.example.com/login/callbacks/oidc` as an **Authorized redirect URI**.
3. Google's standard ID token does not include group memberships. You can use the `email` claim as an identity and control access via `allowedGroups` populated with email addresses, or integrate with Google's Admin SDK to populate group claims via a custom OIDC proxy.

```yaml
login:
  oidc:
    enabled: true
    issuerUrl: "https://accounts.google.com"
    clientId: "your-client-id.apps.googleusercontent.com"
    redirectUrl: "https://console.example.com/login/callbacks/oidc"
    usernameClaim: "email"
    avatarClaimKey: "picture"
    # Google does not emit a "groups" claim by default.
    # Use allowedGroups with email addresses or a custom claim.
    allowedGroups: ["admin@example.com", "developer@example.com"]
    defaultRole: viewer
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Console exits at startup with "failed to discover OIDC provider" | `issuerUrl` is unreachable or incorrect | Verify the URL and that Console can reach the IdP |
| Users are redirected back to the login page after authenticating | `redirectUrl` does not match the URI registered at the IdP | Ensure the redirect URI matches exactly, including scheme and path |
| Users receive "access denied" after login | No `roleBinding` matches the user's groups | Check `groupClaimKey` and verify the claim is present in the ID token; add a matching binding or set `defaultRole` |
| "cookieEncryptionSecret must be exactly 32 or 64 bytes" | Secret is the wrong length | Generate a new secret with `openssl rand -hex 16` (32 bytes) or `openssl rand -hex 32` (64 bytes) |
| Session cookie not persisted across requests in production | `sessionCookieSecure` is `true` but Console is served over plain HTTP | Serve Console over HTTPS, or set `sessionCookieSecure: false` for non-production environments |
