package nucleiSDK

import (
	"context"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
	"time"
)

var opts = &types.Options{
	Debug:                      false,
	DebugRequests:              false,
	DebugResponse:              false,
	Silent:                     false,
	Verbose:                    false,
	NoColor:                    false,
	UpdateTemplates:            false,
	JSONL:                      false,
	OmitRawRequests:            false,
	EnableProgressBar:          false,
	TemplateList:               false,
	Stdin:                      false,
	StopAtFirstMatch:           false,
	NoMeta:                     false,
	Project:                    false,
	MetricsPort:                0,
	BulkSize:                   128,
	TemplateThreads:            32,
	Timeout:                    6,
	Retries:                    1,
	ProbeConcurrency:           50,
	ProjectPath:                "",
	Severities:                 severity.Severities{severity.Medium, severity.High, severity.Critical},
	Targets:                    []string{},
	TargetsFilePath:            "",
	Output:                     "",
	Proxy:                      []string{},
	TraceLogFile:               "",
	ExcludedTemplates:          []string{},
	CustomHeaders:              []string{},
	InteractionsCacheSize:      5000,
	InteractionsEviction:       30,
	InteractionsCoolDownPeriod: 5,
	InteractionsPollDuration:   3,
	GitHubTemplateRepo:         []string{},
	GitHubToken:                "",
	DAST:                       false,
	ProxyInternal:              false,
	Protocols:                  []templateTypes.ProtocolType{templateTypes.HTTPProtocol, templateTypes.NetworkProtocol, templateTypes.JavascriptProtocol},
}

func TestScan(t *testing.T) {
	// 配置测试参数
	pocTemplate := os.Getenv("NUCLEI_POC_TEMPLATE")
	targetFile := os.Getenv("NUCLEI_TARGET_FILE")
	// 如果环境变量未设置，使用默认值或跳过测试
	if pocTemplate == "" {
		t.Skip("NUCLEI_POC_TEMPLATE environment variable not set")
	}
	// 确保模板文件存在
	if _, err := os.Stat(pocTemplate); os.IsNotExist(err) {
		t.Fatalf("Template file %s does not exist", pocTemplate)
	}
	// 准备目标
	var scanTargets []string
	// 确保目标文件存在
	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		t.Fatalf("Target file %s does not exist", targetFile)
	}
	// 读取目标文件
	targetsData, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("Failed to read target file: %v", err)
	}

	// 解析目标
	scanTargets = parseTargets(string(targetsData))
	if len(scanTargets) == 0 {
		t.Skip("No valid targets found in target file")
	}
	t.Logf("Loaded %d targets from file %s", len(scanTargets), targetFile)

	// 创建SDK实例
	sdk, err := NewSDK(opts)
	require.NoError(t, err)
	require.NotNil(t, sdk)

	// 设置结果通道和计数器
	resultChan := make(chan *output.ResultEvent, 10)
	resultCount := 0

	// 创建回调函数
	callback := func(event *output.ResultEvent) error {
		resultChan <- event
		return nil
	}

	// 设置超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 执行扫描
	go func() {
		err := sdk.ExecuteNucleiWithOptsCtx(ctx, scanTargets, callback, SDKOptions(func(opts *types.Options) error {
			// 配置扫描选项
			proxy := os.Getenv("PROXY")
			if proxy != "" {
				opts.Proxy = []string{proxy}
				opts.ProxyInternal = true
			}
			opts.Templates = []string{pocTemplate}
			opts.Verbose = true
			return nil
		}))

		if err != nil {
			t.Logf("Error during scan execution: %v", err)
		}
		close(resultChan)
	}()

	// 收集结果
	results := make([]*output.ResultEvent, 0)
	timeout := time.After(2 * time.Minute)

	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				goto DoneCollecting
			}
			results = append(results, result)
			resultCount++
			t.Logf("Found vulnerability: %s (%s)", result.Info.Name, result.Info.SeverityHolder.Severity.String())
		case <-timeout:
			t.Log("Test timed out after 2 minutes")
			goto DoneCollecting
		}
	}

DoneCollecting:
	t.Logf("Scan completed with %d results", resultCount)

	// 输出详细结果信息
	for i, result := range results {
		t.Logf("Result %d:\n", i+1)
		t.Logf("  Template: %s", result.TemplateID)
		t.Logf("  Name: %s", result.Info.Name)
		t.Logf("  Severity: %s", result.Info.SeverityHolder.Severity.String())
		t.Logf("  Host: %s", result.Host)
		t.Logf("  Matched: %s", result.Matched)
		t.Logf("  Type: %s", result.Type)
		t.Logf("  Timestamp: %s", result.Timestamp)
	}
}

// 辅助函数：解析目标列表
func parseTargets(data string) []string {
	// 简单实现，按行分割
	lines := strings.Split(data, "\n")
	targets := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets
}
