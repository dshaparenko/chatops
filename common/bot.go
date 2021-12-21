package common

import "sync"

type Bot interface {
	Start()
	StartInWaitGroup(wg *sync.WaitGroup)
}
