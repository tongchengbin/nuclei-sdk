package nucleiSDK

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
)

// TemplateSources contains template sources
// which define where to load templates from
type TemplateSources struct {
	Templates       []string // template file/directory paths
	Workflows       []string // workflow file/directory paths
	RemoteTemplates []string // remote template urls
	RemoteWorkflows []string // remote workflow urls
	TrustedDomains  []string // trusted domains for remote templates/workflows
}

// TemplateFilters config contains all SDK configuration options
type TemplateFilters struct {
	Severity             string   // filter by severities (accepts CSV values of info, low, medium, high, critical)
	ExcludeSeverities    string   // filter by excluding severities (accepts CSV values of info, low, medium, high, critical)
	ProtocolTypes        string   // filter by protocol types
	ExcludeProtocolTypes string   // filter by excluding protocol types
	Authors              []string // fiter by author
	Tags                 []string // filter by tags present in template
	ExcludeTags          []string // filter by excluding tags present in template
	IncludeTags          []string // filter by including tags present in template
	IDs                  []string // filter by template IDs
	ExcludeIDs           []string // filter by excluding template IDs
	TemplateCondition    []string // DSL condition/ expression
}

// InteractshOpts contains options for interactsh
type InteractshOpts interactsh.Options

// Concurrency options
type Concurrency struct {
	TemplateConcurrency           int // number of templates to run concurrently (per host in host-spray mode)
	HostConcurrency               int // number of hosts to scan concurrently  (per template in template-spray mode)
	HeadlessHostConcurrency       int // number of hosts to scan concurrently for headless templates  (per template in template-spray mode)
	HeadlessTemplateConcurrency   int // number of templates to run concurrently for headless templates (per host in host-spray mode)
	JavascriptTemplateConcurrency int // number of templates to run concurrently for javascript templates (per host in host-spray mode)
	TemplatePayloadConcurrency    int // max concurrent payloads to run for a template (a good default is 25)
	ProbeConcurrency              int // max concurrent http probes to run (a good default is 50)
}

// HeadlessOpts contains options for headless templates
type HeadlessOpts struct {
	PageTimeout     int // timeout for page load
	ShowBrowser     bool
	HeadlessOptions []string
	UseChrome       bool
}

type StatsOptions struct {
	Interval         int
	JSON             bool
	MetricServerPort int
}

type VerbosityOptions struct {
	Verbose       bool // show verbose output
	Silent        bool // show only results
	Debug         bool // show debug output
	DebugRequest  bool // show request in debug output
	DebugResponse bool // show response in debug output
	ShowVarDump   bool // show variable dumps in output
}

// NetworkConfig contains network config options
// ex: retries , httpx probe , timeout etc
type NetworkConfig struct {
	DisableMaxHostErr     bool     // Disable max host error optimization (Hosts are not skipped even if they are not responding)
	Interface             string   // Interface to use for network scan
	InternalResolversList []string // Use a list of resolver
	LeaveDefaultPorts     bool     // Leave default ports for http/https
	MaxHostError          int      // Maximum number of host errors to allow before skipping that host
	Retries               int      // Number of retries
	SourceIP              string   // SourceIP sets custom source IP address for network requests
	SystemResolvers       bool     // Use system resolvers
	Timeout               int      // Timeout in seconds
	TrackError            []string // Adds given errors to max host error watchlist
}

type OutputWriter output.Writer

type StatsWriter progress.Progress
