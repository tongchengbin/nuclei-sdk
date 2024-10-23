package nucleiSDK

import "strings"

func FormatName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "-", "_"))
}
