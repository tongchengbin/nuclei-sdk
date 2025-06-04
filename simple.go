package nucleiSDK

import (
	"context"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	"log"
	"sync"
	"time"
)

func InitNucleiComponents(opts *types.Options) error {
	if opts.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	} else if opts.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else if opts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
	if err := ValidateOptions(opts); err != nil {
		return err
	}
	if sharedInit == nil || protocolstate.ShouldInit() {
		sharedInit = &sync.Once{}
	}
	sharedInit.Do(func() {
		err := protocolinit.Init(opts)
		if err != nil {
			gologger.Error().Msgf("Could not initialize protocols: %s\n", err)
		}
	})
	return nil
}

type SimpleEngine struct {
	opts         *types.Options
	templateMaps map[string]*templates.Template
	catalog      catalog.Catalog
	executeOpts  protocols.ExecutorOptions
	store        *loader.Store
	Output       output.Writer
	Progress     *progress.Progress
}

func (e *SimpleEngine) LoadAllTemplates() error {
	workflowLoader, err := workflow.NewLoader(&e.executeOpts)
	if err != nil {
		return errorutil.New("Could not create workflow loader: %s\n", err)
	}
	e.executeOpts.WorkflowLoader = workflowLoader

	e.store, err = loader.New(loader.NewConfig(e.opts, e.catalog, e.executeOpts))
	if err != nil {
		return errorutil.New("Could not create loader client: %s\n", err)
	}
	e.store.Load()
	// Load template maps
	e.templateMaps = make(map[string]*templates.Template)
	for _, t := range e.store.Templates() {
		gologger.Debug().Msgf("Loaded template: %s", t.ID)
		e.templateMaps[FormatName(t.ID)] = t
	}
	return nil

}

func (e *SimpleEngine) ExecuteWithProvider(ctx context.Context, targets *provider.SimpleInputProvider, templateNames []string) ([]*output.ResultEvent, error) {
	var tpl *templates.Template
	results := make([]*output.ResultEvent, 0)
	waitEvent := make([]*output.InternalWrappedEvent, 0)
	targets.Iterate(func(target *contextargs.MetaInput) bool {
		for _, templateID := range templateNames {
			var ok bool
			if tpl, ok = e.templateMaps[FormatName(templateID)]; !ok {
				gologger.Error().Msgf("Could not find template '%s'", templateID)
				continue
			}
			ctxArgs := contextargs.New(ctx)
			ctxArgs.MetaInput = target
			ctx := scan.NewScanContext(ctx, ctxArgs)
			ctx.OnResult = func(result *output.InternalWrappedEvent) {
				if len(result.Results) > 0 {
					results = append(results, result.Results...)
				}
				if result.UsesInteractsh && result.InternalEvent != nil && result.InternalEvent["interactsh-url"] != nil {
					waitEvent = append(waitEvent, result)
				}
			}
			_, err := tpl.Executer.ExecuteWithResults(ctx)
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", tpl.ID, err)
			}
		}
		return false
	})
	timeout := time.After(12 * time.Second) // 设置超时时间
	if len(waitEvent) > 0 {
		for _, evt := range waitEvent {
			for {
				select {
				case <-ctx.Done():
					return results, ctx.Err()
				case <-timeout:
					return results, nil
				default:
					if evt.InteractshMatched.Load() {
						if len(evt.Results) > 0 {
							results = append(results, evt.Results...)
							goto outer
						}
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
		outer:
		}
	}

	return results, nil

}

func (e *SimpleEngine) GetTemplates() []*templates.Template {
	return e.store.Templates()
}

func NewSimpleEngine(opts *types.Options) (*SimpleEngine, error) {
	err := InitNucleiComponents(opts)
	if err != nil {
		return nil, err
	}
	e := &SimpleEngine{
		opts: opts,
	}

	if e.catalog == nil {
		e.catalog = disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)
	}

	return e, nil
}

func (e *SimpleEngine) ApplyRequireDefault() error {
	var httpclient *retryablehttp.Client

	if e.opts.ProxyInternal && e.opts.AliveHttpProxy != "" || e.opts.AliveSocksProxy != "" {
		var err error
		httpclient, err = httpclientpool.Get(e.opts, &httpclientpool.Configuration{})
		if err != nil {
			return err
		}
	}
	progressClient := &testutils.MockProgressClient{}
	if e.Output == nil {
		writer := testutils.NewMockOutputWriter(e.opts.OmitTemplate)
		writer.WriteCallback = func(event *output.ResultEvent) {}
		e.Output = writer
	}
	// interactsh
	interactshOpts := interactsh.DefaultOptions(e.Output, nil, progressClient)
	if httpclient == nil {
		httpOpts := retryablehttp.DefaultOptionsSingle
		httpOpts.Timeout = 20 * time.Second // for stability reasons
		if e.opts.Timeout > 20 {
			httpOpts.Timeout = time.Duration(e.opts.Timeout) * time.Second
		}
		// in testing it was found most of times when interactsh failed, it was due to failure in registering /polling requests

		interactshOpts.HTTPClient = retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	} else {
		interactshOpts.HTTPClient = httpclient
	}
	interactshClient, err := interactsh.New(interactshOpts)
	parser := templates.NewParser()
	e.executeOpts = protocols.ExecutorOptions{
		Options:    e.opts,
		Catalog:    e.catalog,
		Interactsh: interactshClient,
		Colorizer:  aurora.NewAurora(true),
		ResumeCfg:  types.NewResumeCfg(),
		Parser:     parser,
	}

	// execute options
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)

	executeOpts := protocols.ExecutorOptions{
		Output:       testutils.NewMockOutputWriter(e.opts.OmitTemplate),
		Options:      e.opts,
		Progress:     progressImpl,
		ProjectFile:  nil,
		IssuesClient: nil,
		Browser:      nil,
		Interactsh:   interactshClient,
		Catalog:      disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		RateLimiter:  ratelimit.New(context.Background(), uint(e.opts.RateLimit), time.Second),
		Parser:       templates.NewParser(),
	}
	workflowLoader, err := workflow.NewLoader(&executeOpts)
	if err != nil {
		log.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executeOpts.WorkflowLoader = workflowLoader
	e.executeOpts = executeOpts
	return nil
}
