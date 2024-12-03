package common

import (
	"sync"

	"github.com/devopsext/utils"
)

type Bot interface {
	Start(wg *sync.WaitGroup)
	Name() string
	Command(channel, text string, user User, parent Message, response Response) error
	AddReaction(channel, ID, name string) error

	PostMessage(channel string, text string, attachments []*Attachment, user User, parent Message, response Response) error
	DeleteMessage(channel, ID string) error
	ReadMessage(channel, ID string) (string, error)
	UpdateMessage(channel, ID, text string) error
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
