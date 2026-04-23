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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1alpha1 "github.com/redpanda-data/console/backend/pkg/protogen/redpanda/api/console/v1alpha1"
)

func TestPermissionsForRole_Admin(t *testing.T) {
	perms := permissionsForRole(RoleAdmin)
	require.NotNil(t, perms)

	// Admin should have ALL Kafka ACL operations.
	allOps := GetAllKafkaACLOperations()
	assert.ElementsMatch(t, allOps, perms.KafkaClusterOperations)

	// Admin should have ALL schema registry capabilities.
	allSR := GetAllSchemaRegistryCapabilities()
	assert.ElementsMatch(t, allSR, perms.SchemaRegistry)

	// Admin should have ALL Redpanda capabilities.
	allRP := GetAllRedpandaCapabilities()
	assert.ElementsMatch(t, allRP, perms.Redpanda)
}

func TestPermissionsForRole_Editor(t *testing.T) {
	perms := permissionsForRole(RoleEditor)
	require.NotNil(t, perms)

	// Editor should have common write operations.
	assert.Contains(t, perms.KafkaClusterOperations, v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_READ)
	assert.Contains(t, perms.KafkaClusterOperations, v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_WRITE)
	assert.Contains(t, perms.KafkaClusterOperations, v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_CREATE)
	assert.Contains(t, perms.KafkaClusterOperations, v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_DELETE)

	// Editor should have schema registry write capabilities.
	assert.Contains(t, perms.SchemaRegistry, v1alpha1.SchemaRegistryCapability_SCHEMA_REGISTRY_CAPABILITY_READ)
	assert.Contains(t, perms.SchemaRegistry, v1alpha1.SchemaRegistryCapability_SCHEMA_REGISTRY_CAPABILITY_WRITE)

	// Editor should NOT have admin Redpanda capabilities.
	assert.NotContains(t, perms.Redpanda, v1alpha1.RedpandaCapability_REDPANDA_CAPABILITY_MANAGE_RBAC)
	assert.NotContains(t, perms.Redpanda, v1alpha1.RedpandaCapability_REDPANDA_CAPABILITY_MANAGE_REDPANDA_USERS)
}

func TestPermissionsForRole_Viewer(t *testing.T) {
	perms := permissionsForRole(RoleViewer)
	require.NotNil(t, perms)

	// Viewer should only have read operations.
	assert.Contains(t, perms.KafkaClusterOperations, v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_READ)
	assert.Contains(t, perms.KafkaClusterOperations, v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_DESCRIBE)
	assert.NotContains(t, perms.KafkaClusterOperations, v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_WRITE)
	assert.NotContains(t, perms.KafkaClusterOperations, v1alpha1.KafkaAclOperation_KAFKA_ACL_OPERATION_DELETE)

	// Viewer should only have schema registry read.
	assert.Equal(t, []v1alpha1.SchemaRegistryCapability{
		v1alpha1.SchemaRegistryCapability_SCHEMA_REGISTRY_CAPABILITY_READ,
	}, perms.SchemaRegistry)

	// Viewer should have no Redpanda capabilities.
	assert.Empty(t, perms.Redpanda)
}

func TestPermissionsForRole_Unknown(t *testing.T) {
	perms := permissionsForRole("")
	require.NotNil(t, perms)
	assert.Empty(t, perms.KafkaClusterOperations)
	assert.Empty(t, perms.SchemaRegistry)
	assert.Empty(t, perms.Redpanda)
}

func TestPermissionsForRole_UnknownRole(t *testing.T) {
	perms := permissionsForRole("superadmin-not-a-real-role")
	require.NotNil(t, perms)
	assert.Empty(t, perms.KafkaClusterOperations)
}
