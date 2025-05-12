package nucleiSDK

import (
	"context"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/zeebo/assert"
	"testing"
)

func TestSimpleEngine(t *testing.T) {
	opts := testutils.DefaultOptions
	opts.Proxy = []string{"http://127.0.0.1:8080"}
	opts.ProxyInternal = true
	opts.Debug = true
	opts.Verbose = true
	opts.VerboseVerbose = true
	opts.Templates = []string{"test-dns.yaml"}
	eg, err := NewSimpleEngine(opts)
	assert.Nil(t, err)
	err = eg.ApplyRequireDefault()
	assert.Nil(t, err)
	err = eg.LoadAllTemplates()
	assert.Equal(t, 1, len(eg.templateMaps))
	assert.Nil(t, err)
	results, err := eg.ExecuteWithProvider(context.Background(), provider.NewSimpleInputProviderWithUrls("http://127.0.0.1:5000"), []string{"test-dns"})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(results))
}
