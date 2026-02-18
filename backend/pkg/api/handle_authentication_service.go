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
	"errors"

	"connectrpc.com/connect"

	"github.com/redpanda-data/console/backend/pkg/auth/oidc"
	v1alpha1 "github.com/redpanda-data/console/backend/pkg/protogen/redpanda/api/console/v1alpha1"
	"github.com/redpanda-data/console/backend/pkg/protogen/redpanda/api/console/v1alpha1/consolev1alpha1connect"
)

// Console role names that match config.RoleBinding.RoleName values.
const (
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

var _ consolev1alpha1connect.AuthenticationServiceHandler = (*OIDCAuthenticationHandler)(nil)

// OIDCAuthenticationHandler is the ConnectRPC AuthenticationService handler
// used when OIDC authentication is enabled.
type OIDCAuthenticationHandler struct{}

// ListAuthenticationMethods informs the frontend that OIDC is the active
// authentication method.
func (*OIDCAuthenticationHandler) ListAuthenticationMethods(
	_ context.Context,
	_ *connect.Request[v1alpha1.ListAuthenticationMethodsRequest],
) (*connect.Response[v1alpha1.ListAuthenticationMethodsResponse], error) {
	res := &v1alpha1.ListAuthenticationMethodsResponse{
		Methods: []v1alpha1.AuthenticationMethod{v1alpha1.AuthenticationMethod_AUTHENTICATION_METHOD_OIDC},
	}
	return connect.NewResponse(res), nil
}

// LoginSaslScram is not applicable when OIDC authentication is enabled.
func (*OIDCAuthenticationHandler) LoginSaslScram(
	_ context.Context,
	_ *connect.Request[v1alpha1.LoginSaslScramRequest],
) (*connect.Response[v1alpha1.LoginSaslScramResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented,
		errors.New("SASL/SCRAM login is not available when OIDC authentication is enabled"))
}

// GetIdentity returns the identity of the currently authenticated user as well
// as the permissions derived from their Console role.
func (*OIDCAuthenticationHandler) GetIdentity(
	ctx context.Context,
	_ *connect.Request[v1alpha1.GetIdentityRequest],
) (*connect.Response[v1alpha1.GetIdentityResponse], error) {
	identity := oidc.UserIdentityFromContext(ctx)
	if identity == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no session found"))
	}

	res := &v1alpha1.GetIdentityResponse{
		DisplayName:          identity.DisplayName,
		AuthenticationMethod: v1alpha1.AuthenticationMethod_AUTHENTICATION_METHOD_OIDC,
		AvatarUrl:            identity.AvatarURL,
		Permissions:          permissionsForRole(identity.Role),
	}
	return connect.NewResponse(res), nil
}

// ListConsoleUsers is not implemented in the open-source edition.
func (*OIDCAuthenticationHandler) ListConsoleUsers(
	_ context.Context,
	_ *connect.Request[v1alpha1.ListConsoleUsersRequest],
) (*connect.Response[v1alpha1.ListConsoleUsersResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented,
		errors.New("ListConsoleUsers requires an enterprise license"))
}

// permissionsForRole converts a Console role name into the corresponding
// set of Kafka, Schema Registry and Redpanda capabilities that will be sent
// to the frontend.
func permissionsForRole(role string) *v1alpha1.GetIdentityResponse_Permissions {
	switch role {
	case RoleAdmin:
		return &v1alpha1.GetIdentityResponse_Permissions{
			KafkaClusterOperations: GetAllKafkaACLOperations(),
			SchemaRegistry:         GetAllSchemaRegistryCapabilities(),
			Redpanda:               GetAllRedpandaCapabilities(),
		}
	case RoleEditor:
		return &v1alpha1.GetIdentityResponse_Permissions{
			KafkaClusterOperations: []v1alpha1.KafkaAclOperation{
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_READ,
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_WRITE,
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_CREATE,
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_DELETE,
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_ALTER,
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_DESCRIBE,
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_DESCRIBE_CONFIGS,
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_ALTER_CONFIGS,
			},
			SchemaRegistry: []v1alpha1.SchemaRegistryCapability{
				v1alpha1.SchemaRegistryCapability_SCHEMA_REGISTRY_CAPABILITY_READ,
				v1alpha1.SchemaRegistryCapability_SCHEMA_REGISTRY_CAPABILITY_WRITE,
				v1alpha1.SchemaRegistryCapability_SCHEMA_REGISTRY_CAPABILITY_DELETE,
			},
			Redpanda: []v1alpha1.RedpandaCapability{
				v1alpha1.RedpandaCapability_REDPANDA_CAPABILITY_MANAGE_TRANSFORMS,
			},
		}
	case RoleViewer:
		return &v1alpha1.GetIdentityResponse_Permissions{
			KafkaClusterOperations: []v1alpha1.KafkaAclOperation{
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_READ,
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_DESCRIBE,
				v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_DESCRIBE_CONFIGS,
			},
			SchemaRegistry: []v1alpha1.SchemaRegistryCapability{
				v1alpha1.SchemaRegistryCapability_SCHEMA_REGISTRY_CAPABILITY_READ,
			},
			Redpanda: nil,
		}
	default:
		// No role or unknown role – deny all permissions.
		return &v1alpha1.GetIdentityResponse_Permissions{}
	}
}
