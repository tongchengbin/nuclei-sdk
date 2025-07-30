package nucleiSDK

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/stretchr/testify/assert"
)

func TestReadIgnoreFile(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "nuclei-test")
	assert.Nil(t, err)
	defer os.RemoveAll(tempDir)

	// Create a temporary nuclei ignore file
	ignoreContent := `
tags:
  - tag1
  - tag2
files:
  - path1
  - path2
`
	// Create the .nuclei-ignore file in the temporary directory
	var configDir string
	if runtime.GOOS == "windows" {
		// On Windows, use USERPROFILE and the appropriate path
		configDir = filepath.Join(tempDir, "AppData", "Local", "nuclei")
	} else {
		// On Unix systems, use HOME and the .config path
		configDir = filepath.Join(tempDir, ".config", "nuclei")
	}

	err = os.MkdirAll(configDir, 0755)
	assert.Nil(t, err)

	ignoreFilePath := filepath.Join(configDir, ".nuclei-ignore")
	err = os.WriteFile(ignoreFilePath, []byte(ignoreContent), 0644)
	assert.Nil(t, err)

	// Save original environment variables
	var originalEnv string
	var envKey string
	if runtime.GOOS == "windows" {
		envKey = "USERPROFILE"
		originalEnv = os.Getenv(envKey)
		os.Setenv(envKey, tempDir)
	} else {
		envKey = "HOME"
		originalEnv = os.Getenv(envKey)
		os.Setenv(envKey, tempDir)
	}
	defer os.Setenv(envKey, originalEnv)

	// Call the ReadIgnoreFile function
	ignoreFile := config.ReadIgnoreFile()

	// Verify the ignore file was read correctly
	assert.Equal(t, 2, len(ignoreFile.Tags))
	assert.Equal(t, "tag1", ignoreFile.Tags[0])
	assert.Equal(t, "tag2", ignoreFile.Tags[1])

	assert.Equal(t, 2, len(ignoreFile.Files))
	assert.Equal(t, "path1", ignoreFile.Files[0])
	assert.Equal(t, "path2", ignoreFile.Files[1])
}
