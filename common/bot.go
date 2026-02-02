package common

import (
	"fmt"
	"sync"

	"github.com/devopsext/utils"
)

type MessageStatus string

const (
	MessageStatusPending         MessageStatus = "pending"
	MessageStatusDelivered       MessageStatus = "delivered"
	MessageStatusFailed          MessageStatus = "failed"
	MessageStatusWaitingApproval MessageStatus = "waiting_approval"
	MessageStatusNotFound        MessageStatus = "not_found"
)

type Bot interface {
	Start(wg *sync.WaitGroup)
	Stop()
	Name() string
	// Command executes a command and returns the resulting Message.
	// Returns nil if no message was created (e.g., command not found).
	// The Message.ID() can be used to track status via GetMessageStatus().
	Command(channel, text string, user User, parent Message, response Response) (Message, error)
	// LookupUser finds a user by ID or email (for API calls when event triggered externally)
	LookupUser(identifier string) User
	GetMessageStatus(messageID string) (MessageStatus, error)

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
// Returns the Message for tracking command status.
func (bs *Bots) ExecuteCommand(botName, channel, command, userIdentifier string) (Message, error) {
	bot := bs.FindByName(botName)
	if bot == nil {
		return nil, fmt.Errorf("bot %q not found", botName)
	}

	// Look up user by ID or email to get their allowed commands
	user := bot.LookupUser(userIdentifier)
	if user == nil {
		return nil, fmt.Errorf("user %q not found", userIdentifier)
	}

	response := NewGenericResponse(true)

	return bot.Command(channel, command, user, nil, response)
}

// GetMessageStatus returns the status of a message by its ID.
func (bs *Bots) GetMessageStatus(botName, messageID string) (MessageStatus, error) {
	bot := bs.FindByName(botName)
	if bot == nil {
		return MessageStatusNotFound, fmt.Errorf("bot %q not found", botName)
	}

	return bot.GetMessageStatus(messageID)
}

func NewBots() *Bots {
	return &Bots{}
}
