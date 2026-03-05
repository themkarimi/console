package interceptor

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redpanda-data/console/backend/pkg/auth/oidc"
)

func TestAuditLogInterceptor_LogsRequestDetails(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	in := NewAuditLogInterceptor(logger)

	handler := in.WrapUnary(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return connect.NewResponse[any](nil), nil
	})

	ctx := context.Background()
	req := connect.NewRequest[any](nil)

	_, err := handler(ctx, req)
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, "audit", entry["msg"])
	assert.Equal(t, "unknown", entry["procedure"])
	assert.Equal(t, "ok", entry["status"])
	assert.Contains(t, entry, "timestamp")
	assert.Contains(t, entry, "duration")
}

func TestAuditLogInterceptor_LogsErrorStatus(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	in := NewAuditLogInterceptor(logger)

	handler := in.WrapUnary(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, connect.NewError(connect.CodeNotFound, nil)
	})

	ctx := context.Background()
	req := connect.NewRequest[any](nil)

	_, err := handler(ctx, req)
	require.Error(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, "audit", entry["msg"])
	assert.Equal(t, "not_found", entry["status"])
	assert.Equal(t, "not_found", entry["error_code"])
}

func TestAuditLogInterceptor_LogsUserIdentity(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	in := NewAuditLogInterceptor(logger)

	handler := in.WrapUnary(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return connect.NewResponse[any](nil), nil
	})

	ctx := oidc.WithUserIdentity(context.Background(), &oidc.UserIdentity{
		Subject:     "user-123",
		DisplayName: "Alice",
		Role:        "admin",
	})
	req := connect.NewRequest[any](nil)

	_, err := handler(ctx, req)
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.Equal(t, "user-123", entry["user_subject"])
	assert.Equal(t, "Alice", entry["user_name"])
	assert.Equal(t, "admin", entry["user_role"])
}

func TestAuditLogInterceptor_NoUserIdentity(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	in := NewAuditLogInterceptor(logger)

	handler := in.WrapUnary(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return connect.NewResponse[any](nil), nil
	})

	ctx := context.Background()
	req := connect.NewRequest[any](nil)

	_, err := handler(ctx, req)
	require.NoError(t, err)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	assert.NotContains(t, entry, "user_subject")
	assert.NotContains(t, entry, "user_name")
	assert.NotContains(t, entry, "user_role")
}

func TestAuditLogInterceptor_StreamingPassthrough(t *testing.T) {
	in := NewAuditLogInterceptor(slog.Default())

	clientFunc := func(_ context.Context, _ connect.Spec) connect.StreamingClientConn { return nil }
	wrapped := in.WrapStreamingClient(clientFunc)
	assert.NotNil(t, wrapped)

	handlerFunc := func(_ context.Context, _ connect.StreamingHandlerConn) error { return nil }
	wrappedHandler := in.WrapStreamingHandler(handlerFunc)
	assert.NotNil(t, wrappedHandler)
}
