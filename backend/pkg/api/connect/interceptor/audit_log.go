// Copyright 2025 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package interceptor

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"

	"github.com/redpanda-data/console/backend/pkg/auth/oidc"
)

var _ connect.Interceptor = &AuditLogInterceptor{}

// AuditLogInterceptor logs audit trail entries for all API requests,
// capturing the procedure, user identity, result status, and duration.
type AuditLogInterceptor struct {
	logger *slog.Logger
}

// NewAuditLogInterceptor creates a new AuditLogInterceptor.
func NewAuditLogInterceptor(logger *slog.Logger) *AuditLogInterceptor {
	return &AuditLogInterceptor{logger: logger}
}

// WrapUnary creates an interceptor that logs an audit entry for each unary request.
func (in *AuditLogInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		start := time.Now()

		procedure := procedureName(ctx, req)
		peerAddr := req.Peer().Addr

		response, err := next(ctx, req)

		duration := time.Since(start)
		status := "ok"
		if err != nil {
			status = connect.CodeOf(err).String()
		}

		attrs := []slog.Attr{
			slog.Time("timestamp", start),
			slog.String("procedure", procedure),
			slog.String("peer_address", peerAddr),
			slog.String("status", status),
			slog.Duration("duration", duration),
		}

		if identity := oidc.UserIdentityFromContext(ctx); identity != nil {
			attrs = append(attrs,
				slog.String("user_subject", identity.Subject),
				slog.String("user_name", identity.DisplayName),
				slog.String("user_role", identity.Role),
			)
		}

		if err != nil {
			attrs = append(attrs, slog.String("error_code", connect.CodeOf(err).String()))
		}

		in.logger.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)

		return response, err
	}
}

// WrapStreamingClient is the middleware handler for bidirectional requests from
// the client perspective.
func (*AuditLogInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler is the middleware handler for bidirectional requests from
// the server handling perspective.
func (*AuditLogInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// procedureName extracts the procedure name from the request or gRPC gateway context.
func procedureName(ctx context.Context, req connect.AnyRequest) string {
	procedure := req.Spec().Procedure
	if procedure == "" {
		if path, ok := runtime.RPCMethod(ctx); ok {
			procedure = path
		} else {
			procedure = "unknown"
		}
	}
	return procedure
}
