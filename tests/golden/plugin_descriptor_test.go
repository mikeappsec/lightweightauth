package golden

// Plugin proto wire-compatibility lock for v1.x.
//
// The captured FileDescriptorSet at tests/golden/plugin-v1/plugin.descriptor
// is the v1.0 wire contract for the plugin gRPC API. Every subsequent build
// must be wire-compatible with it: every (message FQN, field number,
// kind, cardinality) recorded in the snapshot MUST still exist in the live
// descriptor with the same number, kind, and cardinality.
//
// New messages and new fields ARE allowed (additive evolution).
// Removing a message, removing a field, renumbering, or changing a field's
// type is NOT allowed within v1.x and will fail this test.
//
// To regenerate the descriptor (e.g. on a v2 cycle), run:
//   UPDATE_GOLDEN=1 go test ./tests/golden/...
// and review the diff carefully before committing.

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	// Pull live FileDescriptors into protoregistry.GlobalFiles via init().
	_ "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
	_ "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
)

const pluginDescriptorPath = "plugin-v1/plugin.descriptor"

// lockedFiles enumerates the proto files whose wire contract is locked at
// v1.0. New proto files added later in v1.x are not auto-locked; add them
// here (and regenerate) to bring them under the lock.
var lockedFiles = []string{
	"lightweightauth/plugin/v1/plugin.proto",
	"lightweightauth/v1/auth.proto",
	"lightweightauth/v1/config_discovery.proto",
}

func buildLiveDescriptorSet(t *testing.T) *descriptorpb.FileDescriptorSet {
	t.Helper()
	set := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	var add func(fd protoreflect.FileDescriptor)
	add = func(fd protoreflect.FileDescriptor) {
		if seen[fd.Path()] {
			return
		}
		seen[fd.Path()] = true
		// Add deps first so the set is self-contained / topologically sound.
		for i := 0; i < fd.Imports().Len(); i++ {
			add(fd.Imports().Get(i).FileDescriptor)
		}
		set.File = append(set.File, protodesc.ToFileDescriptorProto(fd))
	}
	for _, path := range lockedFiles {
		fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
		if err != nil {
			t.Fatalf("locked file %q not registered in live build: %v", path, err)
		}
		add(fd)
	}
	return set
}

func TestPluginDescriptorLock(t *testing.T) {
	live := buildLiveDescriptorSet(t)

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		blob, err := proto.Marshal(live)
		if err != nil {
			t.Fatalf("marshal live descriptor set: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(pluginDescriptorPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(pluginDescriptorPath, blob, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d bytes, %d files)", pluginDescriptorPath, len(blob), len(live.File))
		return
	}

	blob, err := os.ReadFile(pluginDescriptorPath)
	if err != nil {
		t.Fatalf("read golden: %v (run with UPDATE_GOLDEN=1 to create)", err)
	}
	locked := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(blob, locked); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}

	// Re-resolve the locked set into FileDescriptors so we can walk it
	// the same way we walk the live registry.
	files, err := protodesc.NewFiles(locked)
	if err != nil {
		t.Fatalf("resolve locked descriptor set: %v", err)
	}

	// For every locked message, assert it still exists in the live build,
	// at the same FQN, with every locked field still present at the same
	// number, kind, and cardinality.
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		assertFileBackwardsCompat(t, fd)
		return true
	})
}

func assertFileBackwardsCompat(t *testing.T, lockedFD protoreflect.FileDescriptor) {
	t.Helper()
	msgs := lockedFD.Messages()
	for i := 0; i < msgs.Len(); i++ {
		assertMessageBackwardsCompat(t, msgs.Get(i))
	}
	enums := lockedFD.Enums()
	for i := 0; i < enums.Len(); i++ {
		assertEnumBackwardsCompat(t, enums.Get(i))
	}
	svcs := lockedFD.Services()
	for i := 0; i < svcs.Len(); i++ {
		assertServiceBackwardsCompat(t, svcs.Get(i))
	}
}

func assertMessageBackwardsCompat(t *testing.T, locked protoreflect.MessageDescriptor) {
	t.Helper()
	fqn := locked.FullName()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(fqn)
	if err != nil {
		t.Errorf("v1 wire break: message %q removed from live build (%v)", fqn, err)
		return
	}
	live, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		t.Errorf("v1 wire break: %q changed kind (was message)", fqn)
		return
	}
	lockedFields := locked.Fields()
	for i := 0; i < lockedFields.Len(); i++ {
		lf := lockedFields.Get(i)
		liveField := live.Fields().ByNumber(lf.Number())
		if liveField == nil {
			t.Errorf("v1 wire break: %s field #%d (%s) removed", fqn, lf.Number(), lf.Name())
			continue
		}
		if liveField.Kind() != lf.Kind() {
			t.Errorf("v1 wire break: %s field #%d kind %s -> %s",
				fqn, lf.Number(), lf.Kind(), liveField.Kind())
		}
		if liveField.Cardinality() != lf.Cardinality() {
			t.Errorf("v1 wire break: %s field #%d cardinality %s -> %s",
				fqn, lf.Number(), lf.Cardinality(), liveField.Cardinality())
		}
		// Renaming a field is technically wire-safe but breaks JSON / text
		// proto, so we lock names too.
		if liveField.Name() != lf.Name() {
			t.Errorf("v1 wire break: %s field #%d renamed %q -> %q",
				fqn, lf.Number(), lf.Name(), liveField.Name())
		}
		// For message-typed fields, lock the referenced message FQN so a
		// drive-by re-typing to a different message is caught.
		if lf.Kind() == protoreflect.MessageKind || lf.Kind() == protoreflect.GroupKind {
			if liveField.Message().FullName() != lf.Message().FullName() {
				t.Errorf("v1 wire break: %s field #%d message type %q -> %q",
					fqn, lf.Number(), lf.Message().FullName(), liveField.Message().FullName())
			}
		}
	}
	// Recurse into nested messages so locked nested types are also checked.
	nested := locked.Messages()
	for i := 0; i < nested.Len(); i++ {
		assertMessageBackwardsCompat(t, nested.Get(i))
	}
	nestedEnums := locked.Enums()
	for i := 0; i < nestedEnums.Len(); i++ {
		assertEnumBackwardsCompat(t, nestedEnums.Get(i))
	}
}

func assertEnumBackwardsCompat(t *testing.T, locked protoreflect.EnumDescriptor) {
	t.Helper()
	fqn := locked.FullName()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(fqn)
	if err != nil {
		t.Errorf("v1 wire break: enum %q removed (%v)", fqn, err)
		return
	}
	live, ok := d.(protoreflect.EnumDescriptor)
	if !ok {
		t.Errorf("v1 wire break: %q changed kind (was enum)", fqn)
		return
	}
	values := locked.Values()
	for i := 0; i < values.Len(); i++ {
		lv := values.Get(i)
		liveVal := live.Values().ByNumber(lv.Number())
		if liveVal == nil {
			t.Errorf("v1 wire break: enum %s value %d (%s) removed",
				fqn, lv.Number(), lv.Name())
			continue
		}
		if liveVal.Name() != lv.Name() {
			t.Errorf("v1 wire break: enum %s value %d renamed %q -> %q",
				fqn, lv.Number(), lv.Name(), liveVal.Name())
		}
	}
}

func assertServiceBackwardsCompat(t *testing.T, locked protoreflect.ServiceDescriptor) {
	t.Helper()
	fqn := locked.FullName()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(fqn)
	if err != nil {
		t.Errorf("v1 wire break: service %q removed (%v)", fqn, err)
		return
	}
	live, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		t.Errorf("v1 wire break: %q changed kind (was service)", fqn)
		return
	}
	methods := locked.Methods()
	for i := 0; i < methods.Len(); i++ {
		lm := methods.Get(i)
		liveM := live.Methods().ByName(lm.Name())
		if liveM == nil {
			t.Errorf("v1 wire break: %s.%s removed", fqn, lm.Name())
			continue
		}
		if liveM.Input().FullName() != lm.Input().FullName() {
			t.Errorf("v1 wire break: %s.%s input %q -> %q",
				fqn, lm.Name(), lm.Input().FullName(), liveM.Input().FullName())
		}
		if liveM.Output().FullName() != lm.Output().FullName() {
			t.Errorf("v1 wire break: %s.%s output %q -> %q",
				fqn, lm.Name(), lm.Output().FullName(), liveM.Output().FullName())
		}
		if liveM.IsStreamingClient() != lm.IsStreamingClient() ||
			liveM.IsStreamingServer() != lm.IsStreamingServer() {
			t.Errorf("v1 wire break: %s.%s streaming flags changed", fqn, lm.Name())
		}
	}
}
