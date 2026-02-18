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
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudhut/common/rest"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redpanda-data/console/backend/pkg/auth/oidc"
	"github.com/redpanda-data/console/backend/pkg/config"
	"github.com/redpanda-data/console/backend/pkg/console"
)

// stubConsoleSvc satisfies console.Servicer by embedding the interface. Only
// the methods explicitly overridden return real values; any other method
// panics (guarding against unexpected service calls in authorization tests).
type stubConsoleSvc struct {
	console.Servicer
	topics []*console.TopicSummary
	groups []console.ConsumerGroupOverview
}

func (s *stubConsoleSvc) GetTopicsOverview(_ context.Context) ([]*console.TopicSummary, error) {
	return s.topics, nil
}

func (s *stubConsoleSvc) GetConsumerGroupsOverview(_ context.Context, _ []string) ([]console.ConsumerGroupOverview, *rest.Error) {
	return s.groups, nil
}

func (s *stubConsoleSvc) GetTopicDetails(_ context.Context, _ []string) ([]console.TopicDetails, *rest.Error) {
	return nil, nil
}

func (s *stubConsoleSvc) DeleteTopic(_ context.Context, _ string) *rest.Error {
	return nil
}

func (s *stubConsoleSvc) DeleteConsumerGroup(_ context.Context, _ string) error {
	return nil
}

func (s *stubConsoleSvc) Start(_ context.Context) error { return nil }
func (s *stubConsoleSvc) Stop()                         {}

// makeTestAPI builds a minimal API suitable for handler unit tests.
func makeTestAPI(svc console.Servicer) *API {
	return &API{
		Cfg:        &config.Config{},
		Logger:     slog.Default(),
		ConsoleSvc: svc,
	}
}

// identityWithPermissions creates a UserIdentity that has the given resource
// permissions.  When perms is nil the identity has no ResourcePermissions,
// which means CanAccessResource returns true for everything (backward-compat).
func identityWithPermissions(perms []config.ResourcePermission) *oidc.UserIdentity {
	return &oidc.UserIdentity{
		Subject:             "test-user",
		Role:                "viewer",
		ResourcePermissions: perms,
	}
}

// requestWithIdentity returns a GET request whose context carries the given
// UserIdentity.  If identity is nil the context has no identity (simulating
// unauthenticated or non-OIDC).
func requestWithIdentity(identity *oidc.UserIdentity) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if identity != nil {
		r = r.WithContext(oidc.WithUserIdentity(r.Context(), identity))
	}
	return r
}

// setURLParam injects a chi URL parameter into the request context so that
// rest.GetURLParam can retrieve it in handler unit tests.
func setURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// --- handleGetTopics ---

func TestHandleGetTopics_FiltersToPermittedTopics(t *testing.T) {
	svc := &stubConsoleSvc{
		topics: []*console.TopicSummary{
			{TopicName: "service.orders"},
			{TopicName: "service.users"},
			{TopicName: "internal.audit"},
		},
	}
	a := makeTestAPI(svc)

	identity := identityWithPermissions([]config.ResourcePermission{
		{
			ResourceType: config.ResourceTypeTopic,
			Pattern:      `service\..*`,
			Permission:   config.ResourcePermissionLevelRead,
		},
	})

	w := httptest.NewRecorder()
	a.handleGetTopics()(w, requestWithIdentity(identity))

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "service.orders")
	assert.Contains(t, body, "service.users")
	assert.NotContains(t, body, "internal.audit")
}

func TestHandleGetTopics_AllowsAllWhenNoResourcePermissions(t *testing.T) {
	svc := &stubConsoleSvc{
		topics: []*console.TopicSummary{
			{TopicName: "service.orders"},
			{TopicName: "internal.audit"},
		},
	}
	a := makeTestAPI(svc)

	// No ResourcePermissions → CanAccessResource returns true for everything.
	identity := identityWithPermissions(nil)

	w := httptest.NewRecorder()
	a.handleGetTopics()(w, requestWithIdentity(identity))

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "service.orders")
	assert.Contains(t, body, "internal.audit")
}

func TestHandleGetTopics_AllowsAllWithoutIdentity(t *testing.T) {
	svc := &stubConsoleSvc{
		topics: []*console.TopicSummary{
			{TopicName: "any-topic"},
		},
	}
	a := makeTestAPI(svc)

	w := httptest.NewRecorder()
	// No identity in context (OIDC disabled / unauthenticated path).
	a.handleGetTopics()(w, requestWithIdentity(nil))

	require.Equal(t, http.StatusOK, w.Code)
}

// --- handleGetPartitions (and similar single-topic read handlers) ---

func TestHandleGetPartitions_ForbiddenWhenNoPermission(t *testing.T) {
	// Pass nil for ConsoleSvc since the auth check should prevent any service call.
	a := makeTestAPI(nil)
	identity := identityWithPermissions([]config.ResourcePermission{
		{
			ResourceType: config.ResourceTypeTopic,
			Pattern:      `service\..*`,
			Permission:   config.ResourcePermissionLevelRead,
		},
	})

	w := httptest.NewRecorder()
	r := setURLParam(requestWithIdentity(identity), "topicName", "internal.secret")
	a.handleGetPartitions()(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleGetPartitions_AllowedWhenPermissionMatches(t *testing.T) {
	// The stub returns empty results; we only care that the auth gate is passed
	// (i.e. the response is NOT 403).
	a := makeTestAPI(&stubConsoleSvc{})
	identity := identityWithPermissions([]config.ResourcePermission{
		{
			ResourceType: config.ResourceTypeTopic,
			Pattern:      `service\..*`,
			Permission:   config.ResourcePermissionLevelRead,
		},
	})

	w := httptest.NewRecorder()
	r := setURLParam(requestWithIdentity(identity), "topicName", "service.orders")
	a.handleGetPartitions()(w, r)

	assert.NotEqual(t, http.StatusForbidden, w.Code)
}

// --- handleDeleteTopic ---

func TestHandleDeleteTopic_ForbiddenWhenWriteOnly(t *testing.T) {
	a := makeTestAPI(nil)
	// User only has "write" (not "admin") on service.* topics.
	identity := identityWithPermissions([]config.ResourcePermission{
		{
			ResourceType: config.ResourceTypeTopic,
			Pattern:      `service\..*`,
			Permission:   config.ResourcePermissionLevelWrite,
		},
	})

	w := httptest.NewRecorder()
	r := setURLParam(requestWithIdentity(identity), "topicName", "service.orders")
	a.handleDeleteTopic()(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleDeleteTopic_AllowedWhenAdmin(t *testing.T) {
	a := makeTestAPI(&stubConsoleSvc{})
	identity := identityWithPermissions([]config.ResourcePermission{
		{
			ResourceType: config.ResourceTypeTopic,
			Pattern:      `service\..*`,
			Permission:   config.ResourcePermissionLevelAdmin,
		},
	})

	w := httptest.NewRecorder()
	r := setURLParam(requestWithIdentity(identity), "topicName", "service.orders")
	a.handleDeleteTopic()(w, r)

	// Should NOT be 403; service stub returns nil → other error (but auth gate passed).
	assert.NotEqual(t, http.StatusForbidden, w.Code)
}

// --- handleGetConsumerGroups ---

func TestHandleGetConsumerGroups_FiltersToPermittedGroups(t *testing.T) {
	svc := &stubConsoleSvc{
		groups: []console.ConsumerGroupOverview{
			{GroupID: "cg-orders"},
			{GroupID: "cg-users"},
			{GroupID: "internal-cg"},
		},
	}
	a := makeTestAPI(svc)

	identity := identityWithPermissions([]config.ResourcePermission{
		{
			ResourceType: config.ResourceTypeConsumerGroup,
			Pattern:      `cg-.*`,
			Permission:   config.ResourcePermissionLevelRead,
		},
	})

	w := httptest.NewRecorder()
	a.handleGetConsumerGroups()(w, requestWithIdentity(identity))

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "cg-orders")
	assert.Contains(t, body, "cg-users")
	assert.NotContains(t, body, "internal-cg")
}

// --- handleGetConsumerGroup ---

func TestHandleGetConsumerGroup_ForbiddenWhenNoPermission(t *testing.T) {
	a := makeTestAPI(nil)
	identity := identityWithPermissions([]config.ResourcePermission{
		{
			ResourceType: config.ResourceTypeConsumerGroup,
			Pattern:      `cg-.*`,
			Permission:   config.ResourcePermissionLevelRead,
		},
	})

	w := httptest.NewRecorder()
	r := setURLParam(requestWithIdentity(identity), "groupId", "internal-cg")
	a.handleGetConsumerGroup()(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// --- handleDeleteConsumerGroup ---

func TestHandleDeleteConsumerGroup_ForbiddenWhenReadOnly(t *testing.T) {
	a := makeTestAPI(nil)
	identity := identityWithPermissions([]config.ResourcePermission{
		{
			ResourceType: config.ResourceTypeConsumerGroup,
			Pattern:      `cg-.*`,
			Permission:   config.ResourcePermissionLevelRead,
		},
	})

	w := httptest.NewRecorder()
	r := setURLParam(requestWithIdentity(identity), "groupId", "cg-orders")
	a.handleDeleteConsumerGroup()(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleDeleteConsumerGroup_AllowedWhenWrite(t *testing.T) {
	a := makeTestAPI(&stubConsoleSvc{})
	identity := identityWithPermissions([]config.ResourcePermission{
		{
			ResourceType: config.ResourceTypeConsumerGroup,
			Pattern:      `cg-.*`,
			Permission:   config.ResourcePermissionLevelWrite,
		},
	})

	w := httptest.NewRecorder()
	r := setURLParam(requestWithIdentity(identity), "groupId", "cg-orders")
	a.handleDeleteConsumerGroup()(w, r)

	// Should NOT be 403 (service call may fail with other error, that's OK).
	assert.NotEqual(t, http.StatusForbidden, w.Code)
}
