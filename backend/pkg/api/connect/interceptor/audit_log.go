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
	"strings"

	"connectrpc.com/connect"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/redpanda-data/console/backend/pkg/auth/oidc"
)

var _ connect.Interceptor = &AuditLogInterceptor{}

// AuditLogInterceptor logs audit trail entries for mutating API requests,
// capturing the procedure, user identity, result status, and resource name.
type AuditLogInterceptor struct {
	logger *slog.Logger
}

// NewAuditLogInterceptor creates a new AuditLogInterceptor.
func NewAuditLogInterceptor(logger *slog.Logger) *AuditLogInterceptor {
	return &AuditLogInterceptor{logger: logger}
}

// WrapUnary creates an interceptor that logs an audit entry for each mutating unary request.
func (in *AuditLogInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		procedure := procedureName(ctx, req)

		if !isMutatingProcedure(procedure) {
			return next(ctx, req)
		}

		peerAddr := req.Peer().Addr
		resource := resourceNameFromRequest(req)

		response, err := next(ctx, req)

		if err != nil && connect.CodeOf(err) == connect.CodeUnimplemented {
			return response, err
		}
		status := "ok"
		if err != nil {
			status = connect.CodeOf(err).String()
		}

		attrs := []slog.Attr{
			slog.String("action", actionFromProcedure(procedure)),
			slog.String("peer_address", peerAddr),
			slog.String("status", status),
		}

		if resource != "" {
			attrs = append(attrs, slog.String("resource_name", resource))
		}

		if identity := oidc.UserIdentityFromContext(ctx); identity != nil {
			attrs = append(attrs,
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

// isMutatingProcedure reports whether the procedure name corresponds to a
// create, update, or delete action. It checks the method segment (after the
// last "/") for well-known mutating prefixes.
func isMutatingProcedure(procedure string) bool {
	method := procedure
	if i := strings.LastIndex(procedure, "/"); i >= 0 {
		method = procedure[i+1:]
	}
	for _, prefix := range []string{"Create", "Update", "Delete", "Patch", "Edit", "Set", "Apply", "Publish"} {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}
	return false
}

// actionFromProcedure maps the procedure method prefix to an uppercase action label.
func actionFromProcedure(procedure string) string {
	method := procedure
	if i := strings.LastIndex(procedure, "/"); i >= 0 {
		method = procedure[i+1:]
	}
	for _, prefix := range []string{"Create", "Delete", "Update", "Patch", "Edit", "Set", "Apply", "Publish"} {
		if strings.HasPrefix(method, prefix) {
			return strings.ToUpper(prefix)
		}
	}
	return "UNKNOWN"
}

// resourceNameFromRequest tries to extract a human-readable resource identifier
// from the proto request message by probing well-known name fields.
func resourceNameFromRequest(req connect.AnyRequest) string {
	msg, ok := req.Any().(proto.Message)
	if !ok {
		return ""
	}
	r := msg.ProtoReflect()
	fields := r.Descriptor().Fields()

	// Probe well-known top-level string fields first.
	for _, candidate := range []protoreflect.Name{"name", "topic_name", "role_name", "user_name", "id", "cluster_name"} {
		fd := fields.ByName(candidate)
		if fd == nil || fd.Kind() != protoreflect.StringKind {
			continue
		}
		if val := r.Get(fd).String(); val != "" {
			return val
		}
	}

	// For requests where the resource is wrapped in a nested message
	// (e.g. CreateTopicRequest.topic.name, CreateUserRequest.user.name),
	// probe each top-level message field for a "name" sub-field.
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
			continue
		}
		nested := r.Get(fd).Message()
		if !nested.IsValid() {
			continue
		}
		nameFd := nested.Descriptor().Fields().ByName("name")
		if nameFd == nil || nameFd.Kind() != protoreflect.StringKind {
			continue
		}
		if val := nested.Get(nameFd).String(); val != "" {
			return val
		}
	}

	return ""
}
