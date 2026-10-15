package config

import (
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestLoad_OwnershipDefaulting covers the ownership rule: "officehq" and
// "byoc" are kept, anything else (absent, empty, unknown, wrong case) reads as
// "officehq".
func TestLoad_OwnershipDefaulting(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"absent", `{"collectionUrl":"https://x.example/"}`, OwnershipOfficeHQ},
		{"empty", `{"collectionUrl":"https://x.example/","ownership":""}`, OwnershipOfficeHQ},
		{"officehq", `{"collectionUrl":"https://x.example/","ownership":"officehq"}`, OwnershipOfficeHQ},
		{"byoc", `{"collectionUrl":"https://x.example/","ownership":"byoc"}`, OwnershipBYOC},
		{"unknown", `{"collectionUrl":"https://x.example/","ownership":"corporate"}`, OwnershipOfficeHQ},
		{"wrong case", `{"collectionUrl":"https://x.example/","ownership":"BYOC"}`, OwnershipOfficeHQ},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fake.NewFS()
			fsys.Seed(Path("darwin"), []byte(tc.json))
			cfg, err := Load(fsys, Path("darwin"))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Ownership != tc.want {
				t.Errorf("Ownership = %q, want %q", cfg.Ownership, tc.want)
			}
		})
	}
}

// TestLoad_TenantAndClientAreOptional checks the baked-in Entra values are
// read when present and left empty when absent, and that the enrollment token
// is optional.
func TestLoad_TenantAndClientAreOptional(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(Path("windows"), []byte(`{"collectionUrl":"https://x.example/","tenantId":"t-1","clientId":"c-1"}`))
	cfg, err := Load(fsys, Path("windows"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TenantID != "t-1" || cfg.ClientID != "c-1" {
		t.Errorf("tenant/client = %q/%q, want t-1/c-1", cfg.TenantID, cfg.ClientID)
	}
	if cfg.EnrollmentToken != "" {
		t.Errorf("EnrollmentToken = %q, want empty", cfg.EnrollmentToken)
	}

	fsys.Seed(Path("windows"), []byte(`{"collectionUrl":"https://x.example/"}`))
	cfg, err = Load(fsys, Path("windows"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TenantID != "" || cfg.ClientID != "" {
		t.Errorf("tenant/client = %q/%q, want empty", cfg.TenantID, cfg.ClientID)
	}
}
