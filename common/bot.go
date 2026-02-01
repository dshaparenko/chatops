package common

import (
	"fmt"
	"sync"

	"github.com/devopsext/utils"
)

type Bot interface {
	Start(wg *sync.WaitGroup)
	Stop()
	Name() string
	Command(channel, text string, user User, parent Message, response Response) error
	// for API calls when event triggered not by slack
	LookupUser(identifier string) User

	AddReaction(channel, ID, name string) error
	RemoveReaction(channel, ID, name string) error

	AddAction(channel, ID string, action Action) error
	AddActions(channel, ID string, actions []Action) error
	RemoveAction(channel, ID, name string) error
	ClearActions(channel, ID string) error

	PostMessage(channel string, message string, attachments []*Attachment, actions []Action, user User, parent Message, response Response) (string, error)
	DeleteMessage(channel, ID string) error
	ReadMessage(channel, ID, threadID string) (string, error)
	ReadThread(channel, threadID string) ([]string, error)
	UpdateMessage(channel, ID, message string) error
	TagMessage(channel, ID string, tags map[string]string) error
	FindMessagesByTag(tagKey, tagValue string) map[string]string

	SendImage(channelID, threadTS string, fileContent []byte, filename, initialComment string) error

	AddDivider(channel, ID string) error
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

// Stop calls Stop on each bot in the list
func (bs *Bots) Stop() {
	for _, i := range bs.list {
		if i != nil {
			i.Stop()
		}
	}
}

func (bs *Bots) FindByName(name string) Bot {
	for _, b := range bs.list {
		if b != nil && b.Name() == name {
			return b
		}
	}
	return nil
}

// ExecuteCommand implements CommandExecutor interface.
// notifier is optional - if provided, it will be called when command completes (including after approval).
func (bs *Bots) ExecuteCommand(botName, channel, command, userIdentifier string, notifier StatusNotifier) error {
	bot := bs.FindByName(botName)
	if bot == nil {
		return fmt.Errorf("bot %q not found", botName)
	}

	// Look up user by ID or email to get their allowed commands
	user := bot.LookupUser(userIdentifier)
	if user == nil {
		return fmt.Errorf("user %q not found", userIdentifier)
	}

	response := NewGenericResponseWithNotifier(true, notifier)

	return bot.Command(channel, command, user, nil, response)
}

func NewBots() *Bots {
	return &Bots{}
}
