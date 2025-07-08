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
	RemoveReaction(channel, ID, name string) error

	AddAction(channel, ID string, action Action) error
	AddActions(channel, ID string, actions []Action) error
	RemoveAction(channel, ID, name string) error
	ClearActions(channel, ID string) error

	PostMessage(channel string, message string, attachments []*Attachment, actions []Action, user User, parent Message, response Response) (string, error)
	DeleteMessage(channel, ID string) error
	ReadMessage(channel, ID string) (string, error)
	ReadMessageV2(channel, ID, threadID string) (string, error)
	UpdateMessage(channel, ID, message string) error
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
