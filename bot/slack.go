package bot

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"github.com/shomali11/proper"
	"github.com/slack-go/slack"
	"github.com/slack-io/slacker"
)

type SlackOptions struct {
	BotToken       string
	AppToken       string
	Debug          bool
	ReplyInThread  bool
	ReactionDoing  string
	ReactionDone   string
	ReactionFailed string
	DefaultCommand string
	HelpCommand    string
}

type SlackUser struct {
	id   string
	name string
}

type Slack struct {
	options           SlackOptions
	processors        *common.Processors
	client            *slacker.Slacker
	logger            sreCommon.Logger
	defaultDefinition *slacker.CommandDefinition
	helpDefinition    *slacker.CommandDefinition
}

type SlackRichTextQuoteElement struct {
	Type   slack.RichTextElementType `json:"type"`
	Text   string                    `json:"text,omitempty"`
	UserID string                    `json:"user_id,omitempty"`
}

type SlackRichTextQuote struct {
	Type     slack.RichTextElementType    `json:"type"`
	Elements []*SlackRichTextQuoteElement `json:"elements"`
}

func (r SlackRichTextQuote) RichTextElementType() slack.RichTextElementType {
	return r.Type
}

func (r SlackRichTextQuoteElement) RichTextElementType() slack.RichTextElementType {
	return r.Type
}

// SlackUser

func (su *SlackUser) ID() string {
	return su.id
}

func (su *SlackUser) Name() string {
	return su.name
}

// Slack

func (s *Slack) Name() string {
	return "Slack"
}

/*func (s *Slack) replyDefaultOptions() []slacker.ReplyOption {

	opts := []slacker.ReplyOption{
		slacker.WithInThread(s.options.ReplyInThread),
	}
	return opts
}*/

func (s *Slack) reply(cc *slacker.CommandContext, message string, attachments []slack.Attachment, elapsed *time.Duration, error bool) error {

	userID := cc.Event().UserID
	channelID := cc.Event().ChannelID
	threadTS := cc.Event().ThreadTimeStamp
	typ := cc.Event().Type
	text := cc.Event().Text

	if typ == "slash_commands" {
		text = strings.TrimSpace(text)
	} else {
		items := strings.Split(text, ">")
		if len(items) > 1 {
			text = strings.TrimSpace(items[1])
		}
	}

	replyInThread := s.options.ReplyInThread
	if utils.IsEmpty(threadTS) {
		threadTS = cc.Event().TimeStamp
	} else {
		replyInThread = true
	}

	atts := []slack.Attachment{}
	opts := []slacker.PostOption{}
	if error {
		atts = append(atts, slack.Attachment{
			Color: "danger",
			Text:  message,
		})
	}
	atts = append(atts, attachments...)
	opts = append(opts, slacker.SetAttachments(atts))

	if replyInThread {
		opts = append(opts, slacker.SetThreadTS(threadTS))
	}

	duration := ""
	if elapsed != nil && !error {
		duration = fmt.Sprintf("[%s]", elapsed.Round(time.Millisecond))
	}

	elements := []slack.RichTextElement{
		// add quote
		&SlackRichTextQuote{Type: slack.RTEQuote, Elements: []*SlackRichTextQuoteElement{
			{Type: "text", Text: fmt.Sprintf("%s ", duration)},
			{Type: "user", UserID: userID},
			{Type: "text", Text: fmt.Sprintf(" %s", text)},
		}},
	}

	blocks := []slack.Block{
		slack.NewRichTextBlock("quote", elements...),
	}

	if !error {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", message, false, false),
			[]*slack.TextBlockObject{},
			nil,
		))
	}

	_, err := cc.Response().PostBlocks(channelID, blocks, opts...)
	if err != nil {
		return err
	}
	return nil
}

func (s *Slack) replyMessage(cc *slacker.CommandContext, message string, attachments []slack.Attachment, elapsed *time.Duration) error {
	return s.reply(cc, message, attachments, elapsed, false)
}

func (s *Slack) replyError(cc *slacker.CommandContext, err error, attachments []slack.Attachment) error {
	return s.reply(cc, err.Error(), attachments, nil, true)
}

func (s *Slack) addReaction(cc *slacker.CommandContext, name string) {

	if cc.Event().Type == "slash_commands" {
		return
	}
	err := cc.SlackClient().AddReaction(name, slack.NewRefToMessage(cc.Event().ChannelID, cc.Event().TimeStamp))
	if err != nil {
		s.logger.Error(err)
	}
}

func (s *Slack) removeReaction(cc *slacker.CommandContext, name string) {

	if cc.Event().Type == "slash_commands" {
		return
	}
	err := cc.SlackClient().RemoveReaction(name, slack.NewRefToMessage(cc.Event().ChannelID, cc.Event().TimeStamp))
	if err != nil {
		s.logger.Error(err)
	}
}

func (s *Slack) addRemoveReactions(cc *slacker.CommandContext, first, second string) {
	s.addReaction(cc, first)
	s.removeReaction(cc, second)
}

func (s *Slack) buildCommand(name string, params []string) string {

	r := name
	if len(params) > 0 {
		arr := []string{}
		for _, v := range params {
			arr = append(arr, fmt.Sprintf("{%s}", v))
		}
		r = fmt.Sprintf("%s %s", r, strings.Join(arr, " "))
	}
	return r
}

func (s *Slack) convertProperties(params []string, props *proper.Properties) common.ExecuteParams {

	r := make(common.ExecuteParams)
	if props == nil {
		return r
	}
	for _, v := range params {
		s := props.StringParam(v, "")
		if !utils.IsEmpty(s) {
			r[v] = s
		}
	}
	return r
}

func (s *Slack) convertAttachmentType(typ common.AttachmentType) string {

	switch typ {
	case common.AttachmentTypeUnknown:
		return ""
	case common.AttachmentTypeText:
		return "text"
	case common.AttachmentTypeImage:
		return "image"
	default:
		return "text"
	}

}

func (s *Slack) defaultCommandDefinition(cmd common.Command, groupName string, error bool) *slacker.CommandDefinition {

	cName := cmd.Name()
	params := cmd.Params()
	def := &slacker.CommandDefinition{

		Command:     s.buildCommand(cName, params),
		Description: cmd.Description(),
		HideHelp:    true,
		Handler: func(cc *slacker.CommandContext) {

			s.addReaction(cc, s.options.ReactionDoing)

			r := cc.Request()
			eParams := s.convertProperties(params, r.Properties())
			event := cc.Event()

			user := &SlackUser{
				id: event.UserID,
			}

			profile, err := s.client.SlackClient().GetUserProfile(&slack.GetUserProfileParameters{UserID: event.UserID, IncludeLabels: false})
			if err == nil && profile != nil {
				user.name = profile.DisplayName
			}

			var replyAttachments []slack.Attachment

			t1 := time.Now()
			message, attachments, err := cmd.Execute(s, user, eParams)
			if err != nil {
				s.logger.Error("Slack command %s request execution error: %s", groupName, err)
				s.replyError(cc, err, replyAttachments)
				s.addRemoveReactions(cc, s.options.ReactionFailed, s.options.ReactionDoing)
				return
			}

			// add attachements if some
			if len(attachments) > 0 {
				for _, a := range attachments {
					replyAttachments = append(replyAttachments, slack.Attachment{
						Pretext:    a.Text,
						Title:      a.Title,
						Text:       string(a.Data),
						MarkdownIn: []string{s.convertAttachmentType(a.Type)},
					})
				}
			}
			elapsed := time.Since(t1)
			err = s.reply(cc, message, replyAttachments, &elapsed, false)
			if err != nil {
				s.replyError(cc, err, replyAttachments)
				s.addRemoveReactions(cc, s.options.ReactionFailed, s.options.ReactionDoing)
				return
			}
			if error {
				s.addRemoveReactions(cc, s.options.ReactionFailed, s.options.ReactionDoing)
			} else {
				s.addRemoveReactions(cc, s.options.ReactionDone, s.options.ReactionDoing)
			}
		},
	}
	return def
}

func (s *Slack) unsupportedCommandHandler(cc *slacker.CommandContext) {

	text := cc.Event().Text
	items := strings.Split(text, ">")
	if len(items) > 1 {
		text = strings.TrimSpace(items[1])
	}

	if utils.IsEmpty(text) && s.helpDefinition != nil {
		s.helpDefinition.Handler(cc)
		return
	}

	if s.defaultDefinition != nil {
		s.defaultDefinition.Handler(cc)
		return
	}
}

func (s *Slack) start() {

	client := slacker.NewClient(s.options.BotToken, s.options.AppToken, slacker.WithDebug(s.options.Debug))
	client.UnsupportedCommandHandler(s.unsupportedCommandHandler)

	s.defaultDefinition = nil
	s.helpDefinition = nil

	items := s.processors.Items()
	// add groups firstly
	for _, p := range items {

		pName := p.Name()
		commands := p.Commands()
		var group *slacker.CommandGroup

		if utils.IsEmpty(pName) {
			continue
		}
		group = client.AddCommandGroup(pName)
		for _, c := range commands {
			group.AddCommand(s.defaultCommandDefinition(c, fmt.Sprintf("%s/%s", pName, c.Name()), false))
		}
	}

	group := client.AddCommandGroup("")
	// add root secondly
	for _, p := range items {

		pName := p.Name()
		commands := p.Commands()

		if !utils.IsEmpty(pName) {
			continue
		}
		for _, c := range commands {
			name := c.Name()
			if name == s.options.DefaultCommand {
				s.defaultDefinition = s.defaultCommandDefinition(c, name, true)
			} else {
				def := s.defaultCommandDefinition(c, name, false)
				if name == s.options.HelpCommand {
					s.helpDefinition = def
					client.Help(def)
				}
				group.AddCommand(def)
			}
		}
	}
	s.client = client

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := client.Listen(ctx)
	if err != nil {
		s.logger.Error(err)
		return
	}
}

func (t *Slack) Start(wg *sync.WaitGroup) {

	if wg == nil {
		t.start()
		return
	}

	wg.Add(1)

	go func(wg *sync.WaitGroup) {

		defer wg.Done()
		t.start()
	}(wg)
}

func NewSlack(options SlackOptions, observability *common.Observability, processors *common.Processors) *Slack {

	return &Slack{
		options:    options,
		processors: processors,
		logger:     observability.Logs(),
	}
}
