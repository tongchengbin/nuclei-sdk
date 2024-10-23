package nucleiSDK

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
)

const (
	fgOrange uint8 = 208
)

func GetColorSeverity(templateSeverity severity.Severity) string {
	switch templateSeverity {
	case severity.Info:
		return aurora.Blue(templateSeverity).String()
	case severity.Low:
		return aurora.Green(templateSeverity).String()
	case severity.Medium:
		return aurora.Yellow(templateSeverity).String()
	case severity.High:
		return aurora.Index(fgOrange, templateSeverity).String()
	case severity.Critical:
		return aurora.Red(templateSeverity).String()
	default:

		return aurora.White(templateSeverity).String()
	}
}
