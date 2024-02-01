package bot

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
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
	Permisssions   string
	Timeout        int
	PublicChannel  string
}

type SlackUser struct {
	id   string
	name string
}

type SlackFileResponseFull struct {
	slack.File   `json:"file"`
	slack.Paging `json:"paging"`
	Comments     []slack.Comment        `json:"comments"`
	Files        []slack.File           `json:"files"`
	Metadata     slack.ResponseMetadata `json:"response_metadata"`
	slack.SlackResponse
}

type SlackUploadURLExternalResponse struct {
	UploadURL string `json:"upload_url"`
	FileID    string `json:"file_id"`
	slack.SlackResponse
}

type SlackCompleteUploadExternalResponse struct {
	Files []slack.FileSummary `json:"files"`
	slack.SlackResponse
}

type Slack struct {
	options           SlackOptions
	processors        *common.Processors
	client            *slacker.Slacker
	auth              *slack.AuthTestResponse
	logger            sreCommon.Logger
	meter             sreCommon.Meter
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

type SlackFile struct {
	URL string `json:"url,omitempty"`
	ID  string `json:"id,omitempty"`
}

type SlackImageBlock struct {
	Type      slack.MessageBlockType `json:"type"`
	SlackFile *SlackFile             `json:"slack_file"`
	AltText   string                 `json:"alt_text"`
	BlockID   string                 `json:"block_id,omitempty"`
	Title     *slack.TextBlockObject `json:"title,omitempty"`
}

const (
	slackAPIURL                      = "https://slack.com/api/"
	slackFilesGetUploadURLExternal   = "files.getUploadURLExternal"
	slackFilesCompleteUploadExternal = "files.completeUploadExternal"
	slackFilesSharedPublicURL        = "files.sharedPublicURL"
)

// SlackRichTextQuote
func (r SlackRichTextQuote) RichTextElementType() slack.RichTextElementType {
	return r.Type
}

func (r SlackRichTextQuoteElement) RichTextElementType() slack.RichTextElementType {
	return r.Type
}

// SlackImageBlock
func (s SlackImageBlock) BlockType() slack.MessageBlockType {
	return s.Type
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

func (s *Slack) Info() interface{} {

	if s.auth == nil {
		return nil
	}
	return s.auth
}

func (s *Slack) getEventTextCommand(def *slacker.CommandDefinition, event *slacker.MessageEvent) (string, string) {

	if event == nil {
		return "", ""
	}

	typ := event.Type
	text := event.Text
	command := def.Command

	if typ == "slash_commands" {
		text = strings.TrimSpace(text)
	} else {
		items := strings.SplitAfter(text, ">")

		if len(items) > 1 {
			text = strings.TrimSpace(items[1])
		}
	}

	arr := strings.Split(text, " ")
	if len(arr) > 0 {
		command = strings.TrimSpace(arr[0])
	}

	return text, command
}

/*
func (s *Slack) getBotAuth() string {

	auth := ""
	if !utils.IsEmpty(s.options.BotToken) {
		auth = fmt.Sprintf("Bearer %s", s.options.BotToken)
		return auth
	}
	return auth
}

func (s *Slack) getUserAuth() string {

	auth := ""
	if !utils.IsEmpty(s.options.UserToken) {
		auth = fmt.Sprintf("Bearer %s", s.options.UserToken)
		return auth
	}
	return auth
}


func (s *Slack) ShareFilePublicURL(file *slack.File) (*slack.File, error) {

	client := utils.NewHttpSecureClient(15)

	params := url.Values{}
	params.Add("file", file.ID)

	u, err := url.Parse(slackAPIURL)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, slackFilesSharedPublicURL)
	u.RawQuery = params.Encode()

	data, err := utils.HttpPostRaw(client, u.String(), "application/x-www-form-urlencoded", s.getUserAuth(), nil)
	if err != nil {
		return nil, err
	}

	r := &SlackFileResponseFull{}
	err = json.Unmarshal(data, r)
	if err != nil {
		return nil, err
	}
	if !r.SlackResponse.Ok {
		return nil, errors.New(r.SlackResponse.Error)
	}

	return &r.File, nil
}
*/

func (s *Slack) uploadFileV1(event *slacker.MessageEvent, att *common.Attachment) (string, error) {

	botID := "unknown"
	if s.auth != nil {
		botID = s.auth.BotID
	}
	stamp := time.Now().Format("20060102T150405")
	name := fmt.Sprintf("%s-%s", botID, stamp)
	fileParams := slack.FileUploadParameters{
		Filename: name,
		Reader:   bytes.NewReader(att.Data),
		Channels: []string{s.options.PublicChannel},
	}
	private, err := s.client.SlackClient().UploadFile(fileParams)
	if err != nil {
		return "", err
	}
	/*public, err := s.ShareFilePublicURL(private)
	if err != nil {
		return "", err
	}
	return public.ID, nil*/
	return private.ID, nil
}

func (s *Slack) buildAttachmentBlocks(event *slacker.MessageEvent, attachments []*common.Attachment) ([]slack.Attachment, error) {

	r := []slack.Attachment{}
	for _, a := range attachments {

		blks := []slack.Block{}

		switch a.Type {
		case common.AttachmentTypeImage:

			// uploading image
			id, err := s.uploadFileV1(event, a)
			if err != nil {
				return r, err
			}

			blks = append(blks, &SlackImageBlock{
				Type:    slack.MBTImage,
				AltText: a.Text,
				Title: &slack.TextBlockObject{
					Type: slack.PlainTextType, // only
					Text: a.Title,
				},
				SlackFile: &SlackFile{ID: id},
			})

		default:

			// title
			if !utils.IsEmpty(a.Title) {
				blks = append(blks, slack.NewSectionBlock(
					slack.NewTextBlockObject("mrkdwn", a.Title, false, false),
					[]*slack.TextBlockObject{}, nil,
				))
			}

			// body
			if !utils.IsEmpty(a.Data) {
				blks = append(blks, slack.NewSectionBlock(
					slack.NewTextBlockObject("mrkdwn", string(a.Data), false, false),
					[]*slack.TextBlockObject{}, nil,
				))
			}
		}
		r = append(r, slack.Attachment{
			Color: "808080",
			Blocks: slack.Blocks{
				BlockSet: blks,
			},
		})
	}
	return r, nil
}

func (s *Slack) reply(def *slacker.CommandDefinition, cc *slacker.CommandContext, message string,
	attachments []*common.Attachment, start *time.Time, error bool) error {

	event := cc.Event()
	userID := event.UserID
	channelID := event.ChannelID
	threadTS := event.ThreadTimeStamp
	text, _ := s.getEventTextCommand(def, event)

	replyInThread := s.options.ReplyInThread
	if utils.IsEmpty(threadTS) {
		threadTS = event.TimeStamp
	} else {
		replyInThread = true
	}

	atts := []slack.Attachment{}
	opts := []slacker.PostOption{}
	if error {
		atts = append(atts, slack.Attachment{
			Color: "FF0000",
			Blocks: slack.Blocks{
				BlockSet: []slack.Block{
					slack.NewSectionBlock(slack.NewTextBlockObject("mrkdwn", message, false, false),
						[]*slack.TextBlockObject{}, nil),
				},
			},
		})
		opts = append(opts, slacker.SetAttachments(atts))
	} else {
		batts, err := s.buildAttachmentBlocks(event, attachments)
		if err != nil {
			return err
		}
		opts = append(opts, slacker.SetAttachments(batts))
	}

	if replyInThread {
		opts = append(opts, slacker.SetThreadTS(threadTS))
	}

	// could be used to replace orignal message
	//opts = append(opts, slacker.SetReplace(threadTS))

	// could be visible only for user requested
	//opts = append(opts, slacker.SetEphemeral(userID))

	var quote = []*SlackRichTextQuoteElement{}

	var durationElement *SlackRichTextQuoteElement
	if start != nil && !error && def != s.helpDefinition {

		elapsed := time.Since(*start)
		durationElement = &SlackRichTextQuoteElement{
			Type: "text",
			Text: fmt.Sprintf("[%s] ", elapsed.Round(time.Millisecond)),
		}
		quote = append(quote, durationElement)
	}

	quote = append(quote, []*SlackRichTextQuoteElement{
		{Type: "user", UserID: userID},
		{Type: "text", Text: fmt.Sprintf(" %s", text)},
	}...)

	elements := []slack.RichTextElement{
		// add quote
		&SlackRichTextQuote{Type: slack.RTEQuote, Elements: quote},
	}

	blocks := []slack.Block{
		slack.NewRichTextBlock("quote", elements...),
	}

	if !error {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", message, false, false),
			[]*slack.TextBlockObject{}, nil,
		))
	}

	_, err := cc.Response().PostBlocks(channelID, blocks, opts...)
	if err != nil {
		return err
	}
	return nil
}

func (s *Slack) replyMessage(def *slacker.CommandDefinition, cc *slacker.CommandContext, message string, attachments []*common.Attachment, start *time.Time) error {
	return s.reply(def, cc, message, attachments, start, false)
}

func (s *Slack) replyError(def *slacker.CommandDefinition, cc *slacker.CommandContext, err error, attachments []*common.Attachment) error {
	s.logger.Error("Slack reply error: %s", err)
	return s.reply(def, cc, err.Error(), attachments, nil, true)
}

func (s *Slack) addReaction(cc *slacker.CommandContext, name string) {

	if cc.Event().Type == "slash_commands" {
		return
	}
	err := cc.SlackClient().AddReaction(name, slack.NewRefToMessage(cc.Event().ChannelID, cc.Event().TimeStamp))
	if err != nil {
		s.logger.Error("Slack adding reaction error: %s", err)
	}
}

func (s *Slack) removeReaction(cc *slacker.CommandContext, name string) {

	if cc.Event().Type == "slash_commands" {
		return
	}
	err := cc.SlackClient().RemoveReaction(name, slack.NewRefToMessage(cc.Event().ChannelID, cc.Event().TimeStamp))
	if err != nil {
		s.logger.Error("Slack removing reaction error: %s", err)
	}
}

func (s *Slack) addRemoveReactions(cc *slacker.CommandContext, first, second string) {
	s.addReaction(cc, first)
	s.removeReaction(cc, second)
}

func (s *Slack) findGroup(groups []slack.UserGroup, userID string, group *regexp.Regexp) *slack.UserGroup {

	for _, g := range groups {

		match := group.MatchString(g.Name)
		if match && utils.Contains(g.Users, userID) {
			return &g
		}
	}
	return nil
}

// .*=^(help|news|app|application|catalog)$,some=^(escalate)$
func (s *Slack) denyAccess(userID string, command string) bool {

	if utils.IsEmpty(s.options.Permisssions) {
		return false
	}

	groups, err := s.client.SlackClient().GetUserGroups(slack.GetUserGroupsOptionIncludeCount(true), slack.GetUserGroupsOptionIncludeUsers(true))
	if err != nil {
		s.logger.Error("Slack getting user group error: %s", err)
		return false
	}

	permissions := utils.MapGetKeyValues(s.options.Permisssions)
	for group, value := range permissions {

		reCommand, err := regexp.Compile(value)
		if err != nil {
			s.logger.Error("Slack command regex error: %s", err)
			return true
		}

		mCommand := reCommand.MatchString(command)
		if !mCommand {
			continue
		}

		reGroup, err := regexp.Compile(group)
		if err != nil {
			s.logger.Error("Slack group regex error: %s", err)
			return true
		}

		mGroup := s.findGroup(groups, userID, reGroup)
		if mGroup != nil {
			return false
		}
	}
	return true
}

func (s *Slack) matchParam(text, param string) map[string]string {

	r := make(map[string]string)
	re := regexp.MustCompile(param)
	match := re.FindStringSubmatch(text)
	if len(match) == 0 {
		return r
	}

	names := re.SubexpNames()
	for i, name := range names {
		if i != 0 && name != "" {
			r[name] = match[i]
		}
	}
	return r
}

func (s *Slack) findParams(def *slacker.CommandDefinition, params []string, event *slacker.MessageEvent) common.ExecuteParams {

	r := make(common.ExecuteParams)

	if utils.IsEmpty(params) {
		return r
	}

	if event == nil {
		return r
	}

	text, command := s.getEventTextCommand(def, event)
	arr := strings.SplitAfter(text, command)
	if len(arr) < 2 {
		return r
	}
	text = strings.TrimSpace(arr[1])

	for _, p := range params {
		values := s.matchParam(text, p)
		for k, v := range values {
			r[k] = v
		}
		if len(r) > 0 {
			return r
		}
	}

	return r
}

func (s *Slack) updateCounters(group, command, text string, event *slacker.MessageEvent) {

	labels := make(map[string]string)
	if !utils.IsEmpty(group) {
		labels["group"] = group
	}
	if !utils.IsEmpty(text) {
		labels["command"] = command
	}
	if !utils.IsEmpty(text) {
		labels["text"] = text
	}
	labels["user_id"] = event.UserID

	s.meter.Counter("requests", "Count of all requests", labels, "slack", "bot").Inc()
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
	s.updateCounters("", "", text, cc.Event())
}

func (s *Slack) defaultCommandDefinition(cmd common.Command, group string, error bool) *slacker.CommandDefinition {

	cName := cmd.Name()
	params := cmd.Params()
	def := &slacker.CommandDefinition{
		Command:     cName,
		Aliases:     cmd.Aliases(),
		Description: cmd.Description(),
		HideHelp:    true,
	}
	def.Handler = func(cc *slacker.CommandContext) {

		event := cc.Event()

		text, _ := s.getEventTextCommand(def, event)
		s.updateCounters(group, cName, text, event)

		userID := event.UserID

		groupName := cName
		if !utils.IsEmpty(group) {
			groupName = fmt.Sprintf("%s/%s", group, cName)
		}

		if (def != s.defaultDefinition) && (def != s.helpDefinition) {
			if s.denyAccess(userID, groupName) {
				s.logger.Debug("Slack user %s is not permitted to execute %s", userID, groupName)
				s.unsupportedCommandHandler(cc)
				return
			}
		}

		s.addReaction(cc, s.options.ReactionDoing)

		user := &SlackUser{
			id: userID,
		}

		profile := cc.Event().UserProfile
		if profile != nil {
			user.name = profile.DisplayName
		}

		start := time.Now()
		eParams := s.findParams(def, params, cc.Event())
		message, attachments, err := cmd.Execute(s, user, eParams)

		if err != nil {
			s.logger.Error("Slack command %s request execution error: %s", groupName, err)
			s.replyError(def, cc, err, attachments)
			s.addRemoveReactions(cc, s.options.ReactionFailed, s.options.ReactionDoing)
			return
		}

		err = s.reply(def, cc, message, attachments, &start, false)
		if err != nil {
			s.replyError(def, cc, err, attachments)
			s.addRemoveReactions(cc, s.options.ReactionFailed, s.options.ReactionDoing)
			return
		}
		if error {
			s.addRemoveReactions(cc, s.options.ReactionFailed, s.options.ReactionDoing)
		} else {
			s.addRemoveReactions(cc, s.options.ReactionDone, s.options.ReactionDoing)
		}
	}
	return def
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
			group.AddCommand(s.defaultCommandDefinition(c, pName, false))
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
				s.defaultDefinition = s.defaultCommandDefinition(c, "", true)
			} else {
				def := s.defaultCommandDefinition(c, "", false)
				if name == s.options.HelpCommand {
					s.helpDefinition = def
					client.Help(def)
				}
				group.AddCommand(def)
			}
		}
	}

	client.AddCommand(&slacker.CommandDefinition{
		Command: "some",
		Handler: func(cc *slacker.CommandContext) {

			happyBtn := slack.NewButtonBlockElement("happy", "true", slack.NewTextBlockObject("plain_text", "Happy 🙂", true, false))
			happyBtn.Style = slack.StylePrimary
			sadBtn := slack.NewButtonBlockElement("sad", "false", slack.NewTextBlockObject("plain_text", "Sad ☹️", true, false))
			sadBtn.Style = slack.StyleDanger

			cc.Response().ReplyBlocks([]slack.Block{
				slack.NewSectionBlock(slack.NewTextBlockObject(slack.PlainTextType, "What is your mood today?", true, false), nil, nil),
				slack.NewActionBlock("some", happyBtn, sadBtn),
			})
		},
	})

	client.AddInteraction(&slacker.InteractionDefinition{
		InteractionID: "some",
		Type:          slack.InteractionTypeBlockActions,
		Handler: func(ic *slacker.InteractionContext) {

			text := ""
			action := ic.Callback().ActionCallback.BlockActions[0]
			switch action.ActionID {
			case "happy":
				text = "I'm happy to hear you are happy!"
			case "sad":
				text = "I'm sorry to hear you are sad."
			default:
				text = "I don't understand your mood..."
			}

			ic.Response().Reply(text, slacker.WithReplace(ic.Callback().Message.Timestamp))
		},
	})

	s.client = client
	auth, err := client.SlackClient().AuthTest()
	if err == nil {
		s.auth = auth
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = client.Listen(ctx)
	if err != nil {
		s.logger.Error("Slack listen error: %s", err)
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
		meter:      observability.Metrics(),
	}
}
