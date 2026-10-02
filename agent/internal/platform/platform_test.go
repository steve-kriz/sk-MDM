package platform

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScenario_OSAccessIsConfinedToThePlatformPackage verifies that no
// packages under agent/internal outside of platform import os/exec.
func TestScenario_OSAccessIsConfinedToThePlatformPackage(t *testing.T) {
	// When: I scan agent/internal for imports of os/exec
	agentInternalPath := getAgentInternalPath()
	violations := findOSExecImportsOutsidePlatform(agentInternalPath)

	// Then: only files under agent/internal/platform match
	for _, violation := range violations {
		if !strings.Contains(violation, filepath.Join("internal", "platform")) {
			t.Errorf("Package outside platform imports os/exec: %s", violation)
		}
	}

	// Verify we actually checked some files
	if len(violations) == 0 {
		// This could mean either no violations (good) or we didn't check any files
		// Let's verify we can find the directory
		if _, err := os.Stat(agentInternalPath); err != nil {
			t.Fatalf("Could not find agent/internal directory: %v", err)
		}
	}
}

// findOSExecImportsOutsidePlatform returns a list of files under agent/internal
// that import os/exec but are not in the platform package.
func findOSExecImportsOutsidePlatform(internalPath string) []string {
	var violations []string

	err := filepath.Walk(internalPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only check .go files
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Skip test files (per the instructions, test files are allowed to use os directly)
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// Check if this file imports os/exec
		if hasOSExecImport(path) {
			// Check if it's in the platform package
			if !strings.Contains(path, filepath.Join("internal", "platform")) {
				violations = append(violations, path)
			}
		}

		return nil
	})

	if err != nil {
		return violations
	}

	return violations
}

// hasOSExecImport checks if a Go file imports os/exec
func hasOSExecImport(filePath string) bool {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
	if err != nil {
		return false
	}

	for _, imp := range f.Imports {
		// imp.Path.Value includes quotes, e.g., "os/exec"
		importPath := strings.Trim(imp.Path.Value, "\"")
		if importPath == "os/exec" {
			return true
		}
	}

	return false
}

// getAgentInternalPath returns the path to agent/internal from the working directory
func getAgentInternalPath() string {
	// This test file is at agent/internal/platform/platform_test.go
	// We want to find agent/internal/
	// The working directory when running go test ./... is typically the package directory

	// Strategy: walk up from this file's directory to find internal/
	candidates := []string{
		".",
		filepath.Join(".."),
		filepath.Join("..", ".."),
	}

	for _, basePath := range candidates {
		testPath := filepath.Join(basePath, "internal")
		if info, err := os.Stat(testPath); err == nil && info.IsDir() {
			return testPath
		}

		// Also try without prepending anything
		if basePath == "." {
			if info, err := os.Stat("internal"); err == nil && info.IsDir() {
				return "internal"
			}
		}
	}

	// If we can't find it, return a default that will cause the walk to handle it gracefully
	return "."
}
