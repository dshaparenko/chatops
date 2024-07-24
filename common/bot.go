package common

import (
	"sync"

	"github.com/devopsext/utils"
)

type Bot interface {
	Start(wg *sync.WaitGroup)
	Name() string
	Post(channel string, message string, attachments []*Attachment, parent Message, response Response) error
	Delete(channel, message string) error
}

type Bots struct {
	list []Bot
}

func (bs *Bots) Add(b Bot) {
	if !utils.IsEmpty(b) {
		bs.list = append(bs.list, b)
	}
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
