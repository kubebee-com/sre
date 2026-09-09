package apiv1_test

import (
	"testing"

	"github.com/kubebee-com/sre/api/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

func TestVersionedProtoRegistersExpectedServices(t *testing.T) {
	file := apiv1.File_api_v1_sre_proto
	if file == nil {
		t.Fatal("generated protobuf file descriptor is nil")
	}
	if got, want := file.Path(), "api/v1/sre.proto"; got != want {
		t.Fatalf("descriptor path = %q, want %q", got, want)
	}

	for _, name := range []string{
		"sre.api.v1.AnalyzerService",
		"sre.api.v1.QueryService",
		"sre.api.v1.ConfigService",
	} {
		if _, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name)); err != nil {
			t.Fatalf("service %q is not registered: %v", name, err)
		}
	}
}
