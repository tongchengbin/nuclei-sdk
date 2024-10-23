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
	"log"
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

	InitNucleiComponents(testutils.DefaultOptions)
	Template, err := templates.Parse("C:\\Users\\tongc\\nuclei-templates\\http\\cves\\2024\\CVE-2024-4040.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifer if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "http://127.0.0.1:8080")
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}
