// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package spicedb

import (
	"context"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/grpc"
)

// PermissionChecker is the adapter interface for SpiceDB's
// CheckPermission RPC. It decouples the authorizer from the concrete
// SpiceDB SDK, enabling:
//   - Process-wide gRPC connection sharing (via connpool)
//   - Mock injection for unit tests (no real SpiceDB needed)
//   - Future migration to alternative Zanzibar implementations
//
// The production implementation wraps authzed.Client directly (it
// satisfies this interface natively).
type PermissionChecker interface {
	CheckPermission(ctx context.Context, req *v1.CheckPermissionRequest, opts ...grpc.CallOption) (*v1.CheckPermissionResponse, error)
}
