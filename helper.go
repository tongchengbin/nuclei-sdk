package nucleiSDK

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

// helper.go file proxy execution of all nuclei functions that are nested deep inside multiple packages
// but are helpful / useful while using nuclei as a library

// DefaultConfig is instance of default nuclei configs
// any mutations to this config will be reflected in all nuclei instances (saves some config to disk)
var DefaultConfig *config.Config

func init() {
	DefaultConfig = config.DefaultConfig
}
