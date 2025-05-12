package nucleiSDK

import (
	"context"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/assert"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

var executerOpts protocols.ExecutorOptions

func setup() {
	options := testutils.DefaultOptions
	testutils.Init(options)
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)

	executerOpts = protocols.ExecutorOptions{
		Output:       testutils.NewMockOutputWriter(options.OmitTemplate),
		Options:      options,
		Progress:     progressImpl,
		ProjectFile:  nil,
		IssuesClient: nil,
		Browser:      nil,
		Catalog:      disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		RateLimiter:  ratelimit.New(context.Background(), uint(options.RateLimit), time.Second),
		Parser:       templates.NewParser(),
	}
	workflowLoader, err := workflow.NewLoader(&executerOpts)
	if err != nil {
		log.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executerOpts.WorkflowLoader = workflowLoader
}

func TestFlowTemplateWithIndex(t *testing.T) {
	// test
	setup()
	err := InitNucleiComponents(testutils.DefaultOptions)
	assert.NoError(t, err)
	executerOpts.Options.Debug = true
	executerOpts.Options.DebugResponse = true
	executerOpts.Options.DebugRequests = true
	tempFile := filepath.Join(DefaultConfig.TemplatesDirectory, "http\\cves\\2024\\CVE-2024-4040.yaml")
	Template, err := templates.Parse(tempFile, nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifer if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		println(">>>>>>>>>>>>", r.URL.Path)
		switch r.URL.Path {
		case "/WebInterface/":
			w.WriteHeader(http.StatusOK)
			w.Header().Set("currentAuth", "1.1")
			w.Write([]byte("Mock Server"))
		case "/WebInterface/function/":
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "text/xml")
			w.Write([]byte("<response>success</response>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	input := contextargs.NewWithInput(context.Background(), server.URL)
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}
