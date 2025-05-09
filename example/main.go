package main

import (
	"context"
	"encoding/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	nucleiSDK "github.com/tongchengbin/nuclei-sdk"
	"log"
	"os"
	"sync"
	"time"
)

func main() {
	opts := &types.Options{
		Debug:                      true,
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
		BulkSize:                   25,
		TemplateThreads:            32,
		Timeout:                    5,
		Retries:                    1,
		RateLimit:                  150,
		RateLimitDuration:          time.Second,
		ProbeConcurrency:           50,
		ProjectPath:                "",
		Severities:                 severity.Severities{severity.Medium, severity.High, severity.Critical},
		Targets:                    []string{},
		TargetsFilePath:            "",
		Output:                     "",
		Proxy:                      []string{"http://127.0.0.1:10808"},
		TraceLogFile:               "",
		Templates:                  []string{"example/cyberpanel-rce.yaml"},
		ExcludedTemplates:          []string{},
		CustomHeaders:              []string{},
		InteractshURL:              "https://oast.fun",
		InteractionsCacheSize:      5000,
		InteractionsEviction:       60,
		InteractionsCoolDownPeriod: 5,
		InteractionsPollDuration:   5,
		GitHubTemplateRepo:         []string{},
		GitHubToken:                "",
		DAST:                       false,
		ProxyInternal:              true,
		Protocols:                  []templateTypes.ProtocolType{templateTypes.HTTPProtocol, templateTypes.NetworkProtocol, templateTypes.JavascriptProtocol},
	}
	var nucleiSdk *nucleiSDK.SimpleEngine
	var err error
	nucleiSdk, err = nucleiSDK.NewSimpleEngine(opts)
	if err != nil {
		log.Fatal(err)
	}
	err = nucleiSdk.ApplyRequireDefault()
	if err != nil {
		log.Fatal(err)
	}

	err = nucleiSdk.LoadAllTemplates()
	if err != nil {
		log.Fatal(err)
	}
	// custom struct
	inputMeta := struct {
		Poc []string `json:"poc"`
		Url string   `json:"url"`
	}{
		Poc: []string{"cyberpanel_rce"},
		Url: "https://54.93.204.224:8443",
	}
	wg := sync.WaitGroup{}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup, inputMeta struct {
			Poc []string `json:"poc"`
			Url string   `json:"url"`
		}) {
			defer wg.Done()
			input := provider.NewSimpleInputProvider()
			input.Set(inputMeta.Url)
			ctx := context.Background()
			events, err := nucleiSdk.ExecuteWithProvider(ctx, input, inputMeta.Poc)
			if err != nil {
				log.Fatal(err)
			}
			for _, event := range events {
				_, err := json.Marshal(event)
				if err != nil {
					log.Fatalf("Could not marshal event: %s", err)
				}
				bc := nucleiSDK.FormatEvent(event)
				_, _ = os.Stdout.Write(bc)
				_, _ = os.Stdout.Write([]byte("\n"))
			}

		}(&wg, inputMeta)
	}
	wg.Wait()

}
