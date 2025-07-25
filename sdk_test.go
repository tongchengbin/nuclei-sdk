package nucleiSDK

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
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

func TestBulkSize(t *testing.T) {
	// 设置期望的BulkSize值（最大并发连接数）
	expectedBulkSize := 32
	// 创建一个计数器，用于统计当前活跃的连接数
	var activeConnections int32
	var maxConnections int32
	var connectionMutex sync.Mutex
	// 创建HTTP路由器
	router := httprouter.New()
	// 实现一个接口，该接口会睡眠10秒，并统计最大连接数
	router.GET("/sleep", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// 增加活跃连接计数
		connectionMutex.Lock()
		activeConnections++
		// 更新最大连接数
		if activeConnections > maxConnections {
			maxConnections = activeConnections
		}
		connectionMutex.Unlock()
		// 睡眠10秒
		time.Sleep(6 * time.Second)
		// 减少活跃连接计数
		connectionMutex.Lock()
		activeConnections--
		connectionMutex.Unlock()
		// 返回响应
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	// 创建测试服务器
	ts := httptest.NewServer(router)
	defer ts.Close()

	// 创建一个简单的模板文件，用于测试
	templateContent := `id: test-bulk-size
info:
  name: Test Bulk Size
  author: test
  severity: info
  description: Test to verify bulk size functionality

requests:
  - method: GET
    path:
      - "{{BaseURL}}/sleep"
    matchers:
      - type: word
        words:
          - "OK"`
	// 创建临时模板文件
	tempFile, err := os.CreateTemp("", "test-bulk-size-*.yaml")
	assert.Nil(t, err)
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString(templateContent)
	assert.Nil(t, err)
	tempFile.Close()
	// 初始化SDK
	testutils.DefaultOptions.BulkSize = expectedBulkSize
	sdk, err := NewSDK(testutils.DefaultOptions)
	assert.Nil(t, err)
	assert.NotNil(t, sdk)
	// 创建多个目标URL，以便触发多个并发请求
	var targets []string
	for i := 0; i < expectedBulkSize*4; i++ {
		targets = append(targets, ts.URL)
	}
	// 执行测试，设置BulkSize
	_, err = sdk.ExecuteNucleiWithResult(context.Background(), targets, SDKOptions(func(opts *types.Options) error {
		opts.Templates = []string{tempFile.Name()}
		opts.Timeout = 15
		return nil
	}))
	assert.Nil(t, err)
	// 验证最大连接数是否等于设置的BulkSize
	assert.Equal(t, int32(expectedBulkSize), maxConnections)
}
