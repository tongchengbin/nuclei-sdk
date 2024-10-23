package nucleiSDK

import (
	"sync"
)

var sharedInit *sync.Once

type syncOnce struct {
	sync.Once
}

var updateCheckInstance = &syncOnce{}
