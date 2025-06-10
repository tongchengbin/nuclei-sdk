package nucleiSDK

import (
	"context"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// NucleiSDK 它封装了 nuclei 引擎的核心功能
type NucleiSDK struct {
	// Core components
	options       *types.Options
	templateStore map[string]*templates.Template
	// Result handling
	Callback func(*output.ResultEvent) // Executed on results
	// Thread safety
	mutex       sync.RWMutex
	safeOptions *SafeOptions
}

// SafeOptions 包含公共参数，单例模式
type SafeOptions struct {
	catalog catalog.Catalog
	parser  *templates.Parser
}
type UnsafeOptions struct {
	executeOpts protocols.ExecutorOptions
	engine      *core.Engine
}

func (u *UnsafeOptions) Close() {
	if u.executeOpts.Interactsh != nil {
		u.executeOpts.Interactsh.Close()
	}
	if u.executeOpts.Progress != nil {
		u.executeOpts.Progress.Stop()
	}
}

type SDKOptions func(opts *types.Options) error

// NewSDK 返回一个新的 NucleiSDK 实例
// 初始化所有必要的组件，包括日志级别、协议、工作池和目录
func NewSDK(opts *types.Options) (*NucleiSDK, error) {
	// Configure logging based on options
	if opts.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	} else if opts.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else if opts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
	// fix options
	if opts.HeadlessTemplateThreads <= 0 {
		opts.HeadlessTemplateThreads = 1
	}
	safeOptions := &SafeOptions{
		catalog: disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		parser:  templates.NewParser(),
	}
	// Initialize protocols
	sharedInit := &sync.Once{}
	sharedInit.Do(func() {
		err := protocolinit.Init(opts)
		if err != nil {
			gologger.Error().Msgf("Could not initialize protocols: %s", err)
		}
	})

	// Create SDK instance
	sdk := &NucleiSDK{
		options:       opts,
		templateStore: make(map[string]*templates.Template),
		safeOptions:   safeOptions,
	}

	gologger.Debug().Msgf("Initialized NucleiSDK with options: %+v", opts)
	return sdk, nil
}

func (n *NucleiSDK) ExecuteNucleiWithResult(ctx context.Context, targets []string, opts ...SDKOptions) ([]*output.ResultEvent, error) {
	results := make([]*output.ResultEvent, 0)
	callback := func(result *output.ResultEvent) error {
		results = append(results, result)
		return nil
	}
	err := n.ExecuteNucleiWithOptsCtx(ctx, targets, callback, opts...)
	return results, err
}
func (n *NucleiSDK) ExecuteNucleiWithOptsCtx(ctx context.Context, targets []string, callback ResultCallback, opts ...SDKOptions) error {
	//	所有的初始化都需要在这里进行
	baseOpts := *n.options
	for _, opt := range opts {
		if err := opt(&baseOpts); err != nil {
			return err
		}
	}
	err := loadProxyServers(&baseOpts)
	if err != nil {
		return err
	}
	//非线程安全 需要关闭的资源
	unsafeOpts, err := createEphemeralObjects(ctx, n.safeOptions, &baseOpts, callback)
	if err != nil {
		return err
	}
	// cleanup and stop all resources
	defer unsafeOpts.Close()

	// load templates
	workflowLoader, err := workflow.NewLoader(&unsafeOpts.executeOpts)
	if err != nil {
		return errorutil.New("Could not create workflow loader: %s\n", err)
	}
	unsafeOpts.executeOpts.WorkflowLoader = workflowLoader
	store, err := loader.New(loader.NewConfig(&baseOpts, n.safeOptions.catalog, unsafeOpts.executeOpts))
	if err != nil {
		return errorutil.New("Could not create loader client: %s\n", err)
	}
	store.Load()
	inputProvider := provider.NewSimpleInputProviderWithUrls(targets...)
	if len(store.Templates()) == 0 && len(store.Workflows()) == 0 {
		return errorutil.New("No templates available")
	}
	if inputProvider.Count() == 0 {
		return errorutil.New("No targets available")
	}
	_ = unsafeOpts.engine.ExecuteScanWithOpts(ctx, store.Templates(), inputProvider, false)
	unsafeOpts.engine.WorkPool().Wait()
	return nil
}

// createEphemeralObjects creates ephemeral nuclei objects/instances/types
func createEphemeralObjects(ctx context.Context, safeOpts *SafeOptions, opts *types.Options, callback ResultCallback) (*UnsafeOptions, error) {
	u := &UnsafeOptions{}
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)
	// init http client
	var httpclient *retryablehttp.Client
	var err error
	if opts.ProxyInternal && opts.AliveHttpProxy != "" || opts.AliveSocksProxy != "" {
		httpclient, err = httpclientpool.Get(opts, &httpclientpool.Configuration{})
		if err != nil {
			return nil, err
		}
	}
	if httpclient == nil {
		httpOpts := retryablehttp.DefaultOptionsSingle
		httpOpts.Timeout = 20 * time.Second // for stability reasons
		if opts.Timeout > 20 {
			httpOpts.Timeout = time.Duration(opts.Timeout) * time.Second
		}
		// in testing it was found most of times when interactsh failed, it was due to failure in registering /polling requests
		httpclient = retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	}
	var outputWriter output.Writer
	outputWriter, err = output.NewStandardWriter(opts)
	if err != nil {
		return nil, err
	}
	if callback != nil {
		outputWriter = output.NewMultiWriter(outputWriter, NewCallOutput(callback))

	}
	interactshOpts := interactsh.DefaultOptions(outputWriter, nil, progressImpl)
	interactshOpts.HTTPClient = httpclient
	interactshClient, err := interactsh.New(interactshOpts)
	if err != nil {
		return nil, err
	}

	u.executeOpts = protocols.ExecutorOptions{
		Output:          outputWriter,
		Options:         opts,
		Progress:        progressImpl,
		Catalog:         safeOpts.catalog,
		IssuesClient:    nil,
		RateLimiter:     ratelimit.New(ctx, 150, time.Second),
		Interactsh:      interactshClient,
		HostErrorsCache: nil,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
		Parser:          safeOpts.parser,
		Browser:         nil,
		DoNotCache:      true, // 多任务环境下必须禁止缓存，不然回调无法同步
	}
	if opts.ShouldUseHostError() {
		//HostErrorsCache 是 Nuclei 中用于缓存主机错误信息的组件，它的主要功能是：
		//错误追踪：记录在扫描过程中遇到的与特定主机相关的错误。
		//错误限制：跟踪每个主机发生的错误次数，当错误次数超过某个阈值时，可以选择跳过该主机的后续扫描，避免浪费资源在可能不可达或有问题的主机上。
		//性能优化：通过记住已知的错误状态，避免重复尝试可能会失败的操作，从而提高扫描效率。
		//资源管理：防止因为反复尝试连接不可用主机而浪费资源。
		u.executeOpts.HostErrorsCache = hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	}

	if opts.RateLimit > 0 {
		opts.RateLimitDuration = time.Minute
		u.executeOpts.RateLimiter = ratelimit.New(ctx, uint(opts.RateLimit), opts.RateLimitDuration)
	}
	u.engine = core.New(opts)
	u.engine.SetExecuterOptions(u.executeOpts)
	return u, nil
}
