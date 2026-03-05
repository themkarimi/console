// Copyright 2024 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package oidc

import "context"

type contextKey string

// userIdentityKey is the context key used to store and retrieve a
// *UserIdentity from a context.Context.
const userIdentityKey contextKey = "oidcUserIdentity"

// WithUserIdentity returns a copy of ctx that carries the given *UserIdentity.
func WithUserIdentity(ctx context.Context, identity *UserIdentity) context.Context {
	return context.WithValue(ctx, userIdentityKey, identity)
}

// UserIdentityFromContext returns the *UserIdentity stored in ctx, or nil if
// no identity is present.
func UserIdentityFromContext(ctx context.Context) *UserIdentity {
	v, _ := ctx.Value(userIdentityKey).(*UserIdentity)
	return v
}
