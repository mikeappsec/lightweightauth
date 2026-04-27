// Code generation note (M0):
//
// The .proto files under api/proto/lightweightauth/ are *design artifacts*
// for now. Generated Go code (lightweightauth.v1.Auth, plugin.v1.*) lands
// in M2. Until then, the pipeline is exercised via the HTTP API.
//
// This empty file exists so `go build ./...` walks the directory.
package proto
