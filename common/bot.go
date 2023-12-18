package common

import "sync"

type Bot interface {
	Start(wg *sync.WaitGroup)
	Name() string
}
