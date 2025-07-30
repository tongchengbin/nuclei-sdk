package nucleiSDK

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/zeebo/assert"
)

func TestInteractsh(t *testing.T) {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		value := r.Header.Get("url")
		if value != "" {
			if resp, _ := retryablehttp.DefaultClient().Get(value); resp != nil {
				resp.Body.Close()
			}
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	sdk, err := NewSDK(testutils.DefaultOptions)
	assert.Nil(t, err)
	assert.NotNil(t, sdk)
	result, err := sdk.ExecuteNucleiWithResult(context.Background(), []string{ts.URL}, SDKOptions(func(opts *types.Options) error {
		opts.Proxy = []string{"http://127.0.0.1:8080"}
		opts.ProxyInternal = true
		opts.Debug = true
		opts.Verbose = true
		opts.VerboseVerbose = true
		opts.Templates = []string{"tests/templates"}
		return nil
	}))
	assert.Nil(t, err)
	assert.True(t, len(result) > 0)
}

func TestScanWithResult(t *testing.T) {
	sdk, err := NewSDK(testutils.DefaultOptions)
	assert.Nil(t, err)
	assert.NotNil(t, sdk)
	results, err := sdk.ExecuteNucleiWithResult(context.Background(), []string{"http://127.0.0.1:5000"}, SDKOptions(func(opts *types.Options) error {
		opts.Proxy = []string{"http://127.0.0.1:8080"}
		opts.ProxyInternal = true
		opts.Debug = true
		opts.Verbose = true
		opts.VerboseVerbose = true
		opts.Templates = []string{"test-dns.yaml"}
		return nil
	}))
	assert.Nil(t, err)
	assert.True(t, len(results) > 0)
}

func TestScanMultGlobalCallback(t *testing.T) {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		value := r.Header.Get("url")
		if value != "" {
			if resp, _ := retryablehttp.DefaultClient().Get(value); resp != nil {
				resp.Body.Close()
			}
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	sdk, err := NewSDK(testutils.DefaultOptions)
	assert.Nil(t, err)
	assert.NotNil(t, sdk)
	for i := 0; i < 3; i++ {
		results, err := sdk.ExecuteNucleiWithResult(context.Background(), []string{ts.URL}, SDKOptions(func(opts *types.Options) error {
			opts.Proxy = []string{"http://127.0.0.1:8080"}
			opts.ProxyInternal = true
			opts.Debug = true
			opts.Verbose = true
			opts.VerboseVerbose = true
			opts.Templates = []string{"./tests/templates/interactsh.yaml"}
			return nil
		}))
		assert.Nil(t, err)
		assert.Equal(t, 1, len(results))
	}
}

func TestNucleiIgnore(t *testing.T) {
	sdk, err := NewSDK(testutils.DefaultOptions)
	assert.Nil(t, err)
	assert.NotNil(t, sdk)
	_, err = sdk.ExecuteNucleiWithResult(context.Background(), []string{"http://127.0.0.1:5000"}, SDKOptions(func(opts *types.Options) error {
		opts.Templates = []string{"./tests/templates/fuzz-ignore.yaml"}
		return nil
	}))
	assert.True(t, strings.Contains(err.Error(), "No templates available"))
}
