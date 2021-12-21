package common

import "sync"

type Bots struct {
	list []Bot
}

func (bs *Bots) Add(b Bot) {
	bs.list = append(bs.list, b)
}

func (bs *Bots) Start(wg *sync.WaitGroup) {

	for _, i := range bs.list {

		if i != nil {
			i.Start(wg)
		}
	}
}

func NewBots() *Bots {
	return &Bots{}
}
