package common

import "sync"

type Bots struct {
	list []Bot
}

func (bs *Bots) Add(b Bot) {
	if b != nil {
		bs.list = append(bs.list, b)
	}
}

func (bs *Bots) StartInWaitGroup(wg *sync.WaitGroup) {

	for _, i := range bs.list {

		if i != nil {
			i.StartInWaitGroup(wg)
		}
	}
}

func NewBots() *Bots {
	return &Bots{}
}
