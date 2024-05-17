package bot

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
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
	BotToken        string
	AppToken        string
	Debug           bool
	ReactionDoing   string
	ReactionDone    string
	ReactionFailed  string
	ReactionDialog  string
	DefaultCommand  string
	HelpCommand     string
	Permisssions    string
	Timeout         int
	PublicChannel   string
	AttachmentColor string
	ErrorColor      string
}

type SlackUser struct {
	id       string
	name     string
	timezone string
}

type SlackChannel struct {
	id string
}

type SlackMessage struct {
	id              string
	visible         bool
	threadTimestamp string
	user            *SlackUser
	channel         *SlackChannel
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

type SlackFileBlock struct {
	Type       slack.MessageBlockType `json:"type"`
	ExternalID string                 `json:"external_id"`
	Source     string                 `json:"source"`
	BlockID    string                 `json:"block_id,omitempty"`
}

type SlackButtonValue struct {
	Timestamp string
	Text      string
	Wrapper   string
}

type slackMessageInfo struct {
	typ             string
	text            string
	userID          string
	channelID       string
	timestamp       string
	threadTimestamp string
	wrapper         string
}

const (
	slackAPIURL                      = "https://slack.com/api/"
	slackFilesGetUploadURLExternal   = "files.getUploadURLExternal"
	slackFilesCompleteUploadExternal = "files.completeUploadExternal"
	slackFilesSharedPublicURL        = "files.sharedPublicURL"
	slackMaxTextBlockLength          = 3000
	slackSubmitAction                = "submit"
	slackCancelAction                = "cancel"
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

// SlackFileBlock
func (s SlackFileBlock) BlockType() slack.MessageBlockType {
	return s.Type
}

// SlackUser

func (su *SlackUser) ID() string {
	return su.id
}

func (su *SlackUser) Name() string {
	return su.name
}

func (su *SlackUser) TimeZone() string {
	return su.timezone
}

// SlackChannel

func (sc *SlackChannel) ID() string {
	return sc.id
}

// SlackMessage

func (sm *SlackMessage) ID() string {
	return sm.id
}

func (sm *SlackMessage) Visible() bool {
	return sm.visible
}

func (sm *SlackMessage) User() common.User {
	return sm.user
}

func (sm *SlackMessage) Channel() common.Channel {
	return sm.channel
}

// Slack

func (s *Slack) Name() string {
	return "Slack"
}

/*func (s *Slack) Info() interface{} {

	if s.auth == nil {
		return nil
	}
	return s.auth
}*/

func (s *Slack) getEventTextCommand(command string, m *slackMessageInfo) (string, string) {

	text := m.text
	switch m.typ {
	case "slash_commands":
		text = strings.TrimSpace(text)
	case "app_mention":
		// <@Uq131312> command <param1>  => @bot command param1 param2
		items := strings.SplitN(text, ">", 2)
		if len(items) > 1 {
			text = strings.TrimSpace(items[1])
		}
	case "message":
		// command <param1> param2 => command <param1> param2
		// <@Uq131312> command <param1>  => @bot command param1 param2
		items := strings.SplitN(text, ">", 2)
		if len(items) > 1 && text[0] == '<' {
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

func (s *Slack) uploadFileV1(att *common.Attachment) (*slack.File, error) {

	botID := "unknown"
	if s.auth != nil {
		botID = s.auth.BotID
	}
	stamp := time.Now().Format("20060102T150405")
	name := fmt.Sprintf("%s-%s", botID, stamp)
	params := slack.FileUploadParameters{
		Filename: name,
		Reader:   bytes.NewReader(att.Data),
		Channels: []string{s.options.PublicChannel},
	}
	r, err := s.client.SlackClient().UploadFile(params)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Slack) uploadFileV2(att *common.Attachment) (*slack.FileSummary, error) {

	botID := "unknown"
	if s.auth != nil {
		botID = s.auth.BotID
	}
	stamp := time.Now().Format("20060102T150405")
	name := fmt.Sprintf("%s-%s", botID, stamp)
	params := slack.UploadFileV2Parameters{
		Filename: name,
		FileSize: len(att.Data),
		Reader:   bytes.NewReader(att.Data),
		Channel:  s.options.PublicChannel,
	}
	r, err := s.client.SlackClient().UploadFileV2(params)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Slack) shareFilePublicURL(file *slack.File) (*slack.File, error) {

	r, _, _, err := s.client.SlackClient().ShareFilePublicURL(file.ID)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Slack) addRemoteFile(att *common.Attachment, file *slack.File) (*slack.RemoteFile, error) {

	params := slack.RemoteFileParameters{
		ExternalID:  file.ID,
		ExternalURL: file.PermalinkPublic,
		Title:       att.Title,
	}
	r, err := s.client.SlackClient().AddRemoteFile(params)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Slack) limitText(text string, max int) string {
	r := text
	l := len(text)
	trimmed := "...trimmed :broken_heart:"
	l2 := len(trimmed)
	if l > max {
		r = fmt.Sprintf("%s%s", r[0:max-l2-1], trimmed)
	}
	return r
}

func (s *Slack) buildAttachmentBlocks(attachments []*common.Attachment) ([]slack.Attachment, error) {

	r := []slack.Attachment{}
	for _, a := range attachments {

		blks := []slack.Block{}

		switch a.Type {
		case common.AttachmentTypeImage:

			// uploading image via V1 - important !!!
			f, err := s.uploadFileV2(a)
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
				SlackFile: &SlackFile{ID: f.ID},
			})
		case common.AttachmentTypeFile:

			// uploading file
			/*f, err := s.uploadFileV1(a)
			if err != nil {
				return r, err
			}

			blks = append(blks, &SlackFileBlock{
				Type:       slack.MBTFile,
				ExternalID: f.ID,
				Source:     "remote",
			})*/
		default:

			// title
			if !utils.IsEmpty(a.Title) {
				blks = append(blks,
					slack.NewSectionBlock(
						slack.NewTextBlockObject(slack.MarkdownType, string(a.Title), false, false),
						[]*slack.TextBlockObject{}, nil,
					))
			}

			// body
			if !utils.IsEmpty(a.Data) {

				blks = append(blks,
					slack.NewSectionBlock(
						slack.NewTextBlockObject(slack.MarkdownType, s.limitText(string(a.Data), slackMaxTextBlockLength), false, false),
						[]*slack.TextBlockObject{}, nil,
					))
			}
		}
		r = append(r, slack.Attachment{
			Color: s.options.AttachmentColor,
			Blocks: slack.Blocks{
				BlockSet: blks,
			},
		})
	}
	return r, nil
}

func (s *Slack) addReaction(m *slackMessageInfo, name string) {

	if m.typ == "slash_commands" {
		return
	}
	err := s.client.SlackClient().AddReaction(name, slack.NewRefToMessage(m.channelID, m.timestamp))
	if err != nil {
		s.logger.Error("Slack adding reaction error: %s", err)
	}
}

func (s *Slack) removeReaction(m *slackMessageInfo, name string) {

	if m.typ == "slash_commands" {
		return
	}

	s.client.SlackClient()

	err := s.client.SlackClient().RemoveReaction(name, slack.NewRefToMessage(m.channelID, m.timestamp))
	if err != nil {
		s.logger.Error("Slack removing reaction error: %s", err)
	}
}

func (s *Slack) addRemoveReactions(m *slackMessageInfo, first, second string) {
	s.addReaction(m, first)
	s.removeReaction(m, second)
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

func (s *Slack) matchParam(text, param string) (map[string]string, []string) {

	r := make(map[string]string)
	re := regexp.MustCompile(param)
	match := re.FindStringSubmatch(text)
	if len(match) == 0 {
		return r, []string{}
	}

	names := re.SubexpNames()
	for i, name := range names {
		if i != 0 && name != "" {
			r[name] = match[i]
		}
	}
	return r, names
}

func (s *Slack) findCommandGroup(group string) bool {

	items := s.processors.Items()
	for _, v := range items {
		g := v.Name()
		if g == group {
			return true
		}
	}
	return false
}

func (s *Slack) findCommand(group, command string) common.Command {

	items := s.processors.Items()
	for _, v := range items {
		g := v.Name()
		if g == group {
			for _, v1 := range v.Commands() {
				c := v1.Name()
				if c == command {
					return v1
				}
			}
		}
	}
	return nil
}

func (s *Slack) findParams(wrapper bool, command string, params []string, m *slackMessageInfo) (common.ExecuteParams, common.ExecuteParams, common.Command, string) {

	r := make(common.ExecuteParams)
	rw := make(common.ExecuteParams)

	if utils.IsEmpty(params) {
		return r, rw, nil, ""
	}

	text, command := s.getEventTextCommand(command, m)
	delimiter := command + " "
	arr := strings.SplitN(text, delimiter, 2)
	if len(arr) < 2 {
		return r, rw, nil, ""
	}
	text = strings.TrimSpace(arr[1])

	var keys []string

	for _, p := range params {
		values, ks := s.matchParam(text, p)
		for k, v := range values {
			r[k] = v
		}
		if len(r) > 0 {
			keys = ks
			break
		}
	}
	if !wrapper {
		return r, rw, nil, ""
	}

	// wrapper code
	// show app org params
	if len(keys) > 0 {
		keys := common.RemoveEmptyStrings(keys)

		group := ""
		var c common.Command
		if len(keys) == 1 {
			cmd := fmt.Sprintf("%v", r[keys[0]])
			c = s.findCommand("", cmd)
		}
		if len(keys) > 1 {
			v1 := fmt.Sprintf("%v", r[keys[0]])
			v2 := fmt.Sprintf("%v", r[keys[1]])

			c = s.findCommand("", v1)
			if c != nil {
				group = ""
				delete(r, keys[0])
				r[keys[1]] = c.Name()
			} else {
				group = v1
				c = s.findCommand(group, v2)
			}
		}

		if c == nil {
			return r, rw, nil, ""
		}
		arr := strings.SplitAfter(text, c.Name())
		if len(arr) < 2 {
			return r, rw, c, group
		}
		text = strings.TrimSpace(arr[1])

		r2 := make(common.ExecuteParams)

		for _, p := range c.Params() {
			values, _ := s.matchParam(text, p)
			for k, v := range values {
				r2[k] = v
			}
			if len(r2) > 0 {
				break
			}
		}
		r = common.MergeInterfaceMaps(r, r2)
		return r, r2, c, group
	}

	return r, rw, nil, ""
}

func (s *Slack) updateCounters(group, command, text, userID string) {

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
	labels["user_id"] = userID

	s.meter.Counter("requests", "Count of all requests", labels, "slack", "bot").Inc()
}

func (s *Slack) Delete(channel, message string) error {

	_, _, err := s.client.SlackClient().DeleteMessage(channel, message)

	if err != nil {
		s.logger.Error("Failed to delete message: ", err)
		return err
	}

	s.logger.Info("Message deleted successfully")
	return nil
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
	s.updateCounters("", "", text, cc.Event().UserID)
}

func (s *Slack) reply(command string, m *slackMessageInfo,
	replier interface{}, message string, attachments []*common.Attachment,
	executor common.Executor, start *time.Time, error bool) (string, error) {

	threadTS := m.threadTimestamp
	text, _ := s.getEventTextCommand(command, m)
	replyInThread := !utils.IsEmpty(threadTS)

	visible := false
	original := false
	duration := false

	if !utils.IsEmpty(executor) {

		response := executor.Response()

		if !utils.IsEmpty(response) {
			visible = response.Visible()
			original = response.Original()
			duration = response.Duration()
		}
	}

	atts := []slack.Attachment{}
	opts := []slacker.PostOption{}
	if error {
		atts = append(atts, slack.Attachment{
			Color: s.options.ErrorColor,
			Blocks: slack.Blocks{
				BlockSet: []slack.Block{
					slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
						[]*slack.TextBlockObject{}, nil),
				},
			},
		})
		opts = append(opts, slacker.SetAttachments(atts))
	} else {
		batts, err := s.buildAttachmentBlocks(attachments)
		if err != nil {
			return "", err
		}
		opts = append(opts, slacker.SetAttachments(batts))
	}

	if replyInThread {
		opts = append(opts, slacker.SetThreadTS(threadTS))
	}

	if !visible {
		opts = append(opts, slacker.SetEphemeral(m.userID))
	}

	var quote = []*SlackRichTextQuoteElement{}

	var durationElement *SlackRichTextQuoteElement
	if start != nil && !error && duration {

		elapsed := time.Since(*start)
		durationElement = &SlackRichTextQuoteElement{
			Type: "text",
			Text: fmt.Sprintf("[%s] ", elapsed.Round(time.Millisecond)),
		}
		quote = append(quote, durationElement)
	}

	blocks := []slack.Block{}

	if original {

		if utils.IsEmpty(text) {
			text = command
		}

		if !utils.IsEmpty(m.userID) {
			quote = append(quote, []*SlackRichTextQuoteElement{
				{Type: "user", UserID: m.userID},
			}...)
		}
		quote = append(quote, []*SlackRichTextQuoteElement{
			{Type: "text", Text: fmt.Sprintf(" %s", text)},
		}...)

		elements := []slack.RichTextElement{
			&SlackRichTextQuote{Type: slack.RTEQuote, Elements: quote},
		}
		blocks = append(blocks, slack.NewRichTextBlock("quote", elements...))
	}

	if !error {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
			[]*slack.TextBlockObject{}, nil,
		))
	}

	// ResponseReplier => commands
	rr, ok := replier.(*slacker.ResponseReplier)
	if ok {
		ts, err := rr.PostBlocks(m.channelID, blocks, opts...)
		if err != nil {
			return "", err
		}
		return ts, nil
	}

	// ResponseWriter => jobs
	rw, ok := replier.(*slacker.ResponseWriter)
	if ok {
		ts, err := rw.PostBlocks(m.channelID, blocks, opts...)
		if err != nil {
			return "", err
		}
		return ts, nil
	}

	return "", errors.New("replier is not defined")
}

func (s *Slack) replyError(command string, m *slackMessageInfo,
	replier interface{}, err error, attachments []*common.Attachment) (string, error) {

	s.logger.Error("Slack reply error: %s", err)
	return s.reply(command, m, replier, err.Error(), attachments, nil, nil, true)
}

func (s *Slack) getInteractionID(command, group string) string {

	if utils.IsEmpty(group) {
		return command
	}
	return fmt.Sprintf("%s-%s", command, group)
}

/*func (s *Slack) findParamValue(re *regexp.Regexp, name, text string) string {

	if re == nil {
		return text
	}
	match := re.FindStringSubmatch(text)
	if len(match) != 0 {
		names := re.SubexpNames()
		for i, n := range names {
			if i != 0 && n == name {
				return match[i]
			}
		}
	}
	return text
}*/

func (s *Slack) replyInteraction(command, group string, fields []common.Field, params common.ExecuteParams,
	m *slackMessageInfo, u *slack.User, replier *slacker.ResponseReplier) (bool, error) {

	threadTS := m.threadTimestamp
	opts := []slacker.PostOption{}
	replyInThread := !utils.IsEmpty(threadTS)
	if replyInThread {
		opts = append(opts, slacker.SetThreadTS(threadTS))
	}

	opts = append(opts, slacker.SetEphemeral(m.userID))
	blocks := []slack.Block{}
	interactionID := s.getInteractionID(command, group)

	for _, field := range fields {

		actionID := fmt.Sprintf("%s-%s", interactionID, field.Name)
		def := ""
		if !utils.IsEmpty(params[field.Name]) {
			def = fmt.Sprintf("%v", params[field.Name])
		}
		if utils.IsEmpty(def) {
			def = field.Default
		}

		l := slack.NewTextBlockObject(slack.PlainTextType, field.Label, false, false)
		var h *slack.TextBlockObject
		if !utils.IsEmpty(field.Hint) {
			h = slack.NewTextBlockObject(slack.PlainTextType, field.Hint, false, false)
		}

		var b *slack.InputBlock
		var el slack.BlockElement

		switch field.Type {
		case common.FieldTypeMultiEdit:
			e := slack.NewPlainTextInputBlockElement(h, actionID)
			e.Multiline = true
			e.InitialValue = def
			el = e
		case common.FieldTypeInteger:
			e := slack.NewNumberInputBlockElement(h, actionID, false)
			e.InitialValue = def
			el = e
		case common.FieldTypeFloat:
			e := slack.NewNumberInputBlockElement(h, actionID, true)
			e.InitialValue = def
			el = e
		case common.FieldTypeURL:
			e := slack.NewURLTextInputBlockElement(h, actionID)
			e.InitialValue = def
			el = e
		case common.FieldTypeDate:
			e := slack.NewDatePickerBlockElement(actionID)
			if utils.IsEmpty(def) {
				dateS := time.Now().Format("2006-01-02")
				if u != nil {
					loc, err := time.LoadLocation(u.TZ)
					if err != nil {
						s.logger.Error("Slack couldn't find location: %s", err)
					} else {
						dateS = time.Now().In(loc).Format("2006-01-02")
					}
				}
				e.InitialDate = dateS
			} else {
				dateS := def
				first := strings.TrimSpace(def)
				if utils.Contains([]string{"+", "-"}, first[:1]) {
					d, err := time.ParseDuration(def)
					if err == nil {
						dateS = time.Now().Add(d).Format("2006-01-02")
						if u != nil {
							loc, err := time.LoadLocation(u.TZ)
							if err != nil {
								s.logger.Error("Slack couldn't find location: %s", err)
							} else {
								dateS = time.Now().Add(d).In(loc).Format("2006-01-02")
							}
						}
					}
				}
				e.InitialDate = dateS
			}
			el = e
		case common.FieldTypeTime:
			e := slack.NewTimePickerBlockElement(actionID)
			if utils.IsEmpty(def) {
				timeS := time.Now().Format("15:04")
				if u != nil {
					loc, err := time.LoadLocation(u.TZ)
					if err != nil {
						s.logger.Error("Slack couldn't find location: %s", err)
					} else {
						timeS = time.Now().In(loc).Format("15:04")
					}
				}
				e.InitialTime = timeS
			} else {
				timeS := def
				first := strings.TrimSpace(def)
				if utils.Contains([]string{"+", "-"}, first[:1]) {
					d, err := time.ParseDuration(def)
					if err == nil {
						timeS = time.Now().Add(d).Format("15:04")
						if u != nil {
							loc, err := time.LoadLocation(u.TZ)
							if err != nil {
								s.logger.Error("Slack couldn't find location: %s", err)
							} else {
								timeS = time.Now().Add(d).In(loc).Format("15:04")
							}
						}
					}
				}
				e.InitialTime = timeS
			}
			el = e
		case common.FieldTypeSelect:
			options := []*slack.OptionBlockObject{}
			var dBlock *slack.OptionBlockObject
			for _, v := range field.Values {
				block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h)
				if v == def {
					dBlock = block
				}
				options = append(options, block)
			}
			e := slack.NewOptionsSelectBlockElement(slack.OptTypeStatic, h, actionID, options...)
			if dBlock != nil {
				e.InitialOption = dBlock
			}
			el = e
		case common.FieldTypeMultiSelect:
			options := []*slack.OptionBlockObject{}
			dBlocks := []*slack.OptionBlockObject{}
			arr := common.RemoveEmptyStrings(strings.Split(def, ","))
			for _, v := range field.Values {
				block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h)
				if utils.Contains(arr, v) {
					dBlocks = append(dBlocks, block)
				}
				options = append(options, block)
			}
			e := slack.NewOptionsMultiSelectBlockElement(slack.MultiOptTypeStatic, h, actionID, options...)
			if len(dBlocks) > 0 {
				e.InitialOptions = dBlocks
			}
			el = e
		case common.FieldTypeBool:
			options := []*slack.OptionBlockObject{}
			dBlocks := []*slack.OptionBlockObject{}
			strue := fmt.Sprintf("%v", true)
			block := slack.NewOptionBlockObject(strue, l, nil)
			l = slack.NewTextBlockObject(slack.PlainTextType, " ", false, false)
			options = append(options, block)
			if strue == def {
				dBlocks = append(dBlocks, block)
			}
			e := slack.NewCheckboxGroupsBlockElement(actionID, options...)
			if len(dBlocks) > 0 {
				e.InitialOptions = dBlocks
			}
			el = e
		default:
			e := slack.NewPlainTextInputBlockElement(h, actionID)
			e.InitialValue = def
			el = e
		}

		b = slack.NewInputBlock("", l, nil, el)
		if b != nil {
			b.Optional = !field.Required
			blocks = append(blocks, b)
		}
	}

	if len(blocks) == 0 {
		return false, nil
	}

	// pass message timestamp & text to each button
	value := &SlackButtonValue{
		Timestamp: m.timestamp,
		Text:      m.text,
		Wrapper:   m.wrapper,
	}
	data, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	sv := base64.StdEncoding.EncodeToString(data)

	submit := slack.NewButtonBlockElement(slackSubmitAction, sv, slack.NewTextBlockObject(slack.PlainTextType, "Submit", false, false))
	cancel := slack.NewButtonBlockElement(slackCancelAction, sv, slack.NewTextBlockObject(slack.PlainTextType, "Cancel", false, false))

	ab := slack.NewActionBlock(interactionID, submit, cancel)
	blocks = append(blocks, ab)

	s.addReaction(m, s.options.ReactionDialog)
	_, err = replier.PostBlocks(m.channelID, blocks, opts...)
	if err != nil {
		s.removeReaction(m, s.options.ReactionDialog)
		return false, err
	}
	return true, nil
}

func (s *Slack) postUserCommand(cmd common.Command, m *slackMessageInfo, u *slack.User,
	replier interface{}, params common.ExecuteParams) error {

	cName := cmd.Name()

	user := &SlackUser{
		id: m.userID,
	}
	if u != nil {
		user.name = u.Profile.DisplayName
		user.timezone = u.TZ
	}

	channel := &SlackChannel{
		id: m.channelID,
	}

	msg1 := &SlackMessage{
		id:              m.timestamp,
		user:            user,
		threadTimestamp: m.threadTimestamp,
		channel:         channel,
	}

	s.addReaction(m, s.options.ReactionDoing)

	start := time.Now()
	executor, message, attachments, err := cmd.Execute(s, msg1, params)
	if err != nil {
		s.replyError(cName, m, replier, err, attachments)
		s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
		return err
	}

	visible := false
	error := false
	response := executor.Response()
	if !utils.IsEmpty(response) {
		visible = response.Visible()
		error = response.Error()
	}

	ts, err := s.reply(cName, m, replier, message, attachments, executor, &start, error)
	if err != nil {
		s.replyError(cName, m, replier, err, attachments)
		s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
		return err
	}

	if error {
		s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
	} else {
		s.addRemoveReactions(m, s.options.ReactionDone, s.options.ReactionDoing)
	}

	msg2 := &SlackMessage{
		id:              ts,
		visible:         visible,
		user:            user,
		threadTimestamp: m.threadTimestamp,
		channel:         channel,
	}

	return executor.After(msg2)
}

func (s *Slack) postJobCommand(cmd common.Command, m *slackMessageInfo,
	replier interface{}) error {

	cName := cmd.Name()

	channel := &SlackChannel{
		id: m.channelID,
	}

	msg1 := &SlackMessage{
		id:              m.timestamp,
		threadTimestamp: m.threadTimestamp,
		channel:         channel,
	}

	start := time.Now()
	executor, message, attachments, err := cmd.Execute(s, msg1, nil)
	if err != nil {
		return err
	}

	if utils.IsEmpty(strings.TrimSpace(message)) {
		return nil
	}

	visible := false
	error := false
	response := executor.Response()
	if !utils.IsEmpty(response) {
		visible = response.Visible()
		error = response.Error()
	}

	ts, err := s.reply(cName, m, replier, message, attachments, executor, &start, error)
	if err != nil {
		return err
	}

	msg2 := &SlackMessage{
		id:              ts,
		visible:         visible,
		threadTimestamp: m.threadTimestamp,
		channel:         channel,
	}

	return executor.After(msg2)
}

func (s *Slack) interactionNeeded(fields []common.Field, params map[string]interface{}) bool {

	if params == nil {
		return len(fields) > 0
	}

	arr := []string{}
	keys := common.GetStringKeys(params)

	required := []common.Field{}
	for _, f := range fields {
		if f.Required {
			required = append(required, f)
		}
	}

	for _, f := range required {

		if utils.Contains(keys, f.Name) {
			v := params[f.Name]
			if !utils.IsEmpty(v) {
				arr = append(arr, fmt.Sprintf("%s", v))
			}
		}
	}
	return len(required) > len(arr)
}

func (s *Slack) commandDefinition(cmd common.Command, group string) *slacker.CommandDefinition {

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
		m := &slackMessageInfo{
			typ:             event.Type,
			text:            event.Text,
			userID:          event.UserID,
			channelID:       event.ChannelID,
			timestamp:       event.TimeStamp,
			threadTimestamp: event.ThreadTimeStamp,
		}

		replier := cc.Response()

		user, err := cc.SlackClient().GetUserInfo(m.userID)
		if err != nil {
			s.logger.Error("Slack couldn't get user for %s: %s", m.userID, err)
		}

		text, _ := s.getEventTextCommand(cName, m)
		s.updateCounters(group, cName, text, m.userID)

		groupName := cName
		if !utils.IsEmpty(group) {
			groupName = fmt.Sprintf("%s/%s", group, cName)
		}

		if (def != s.defaultDefinition) && (def != s.helpDefinition) {
			if s.denyAccess(m.userID, groupName) {
				s.logger.Debug("Slack user %s is not permitted to execute %s", m.userID, groupName)
				s.unsupportedCommandHandler(cc)
				return
			}
		}
		wrapper := cmd.Wrapper()
		eParams, wrappedParams, wrappedCmd, wrappedGroup := s.findParams(wrapper, cName, params, m)

		mChannel := &SlackChannel{
			id: m.channelID,
		}

		mUser := &SlackUser{
			id:       m.userID,
			name:     user.Profile.DisplayName,
			timezone: user.TZ,
		}

		msg := &SlackMessage{
			id:              m.timestamp,
			user:            mUser,
			threadTimestamp: m.threadTimestamp,
			channel:         mChannel,
		}

		rCmd := cName
		rGroup := group
		rFields := cmd.Fields(s, msg)
		rParams := eParams

		if wrappedCmd != nil {

			rCmd = wrappedCmd.Name()
			rGroup = wrappedGroup

			wrapperGroupName := rCmd
			if !utils.IsEmpty(rGroup) {
				wrapperGroupName = fmt.Sprintf("%s/%s", rGroup, rCmd)
			}

			if s.denyAccess(m.userID, wrapperGroupName) {
				s.logger.Debug("Slack user %s is not permitted to execute %s", m.userID, wrapperGroupName)
				s.unsupportedCommandHandler(cc)
				return
			}

			rFields = wrappedCmd.Fields(s, msg)
			rParams = wrappedParams
			m.wrapper = fmt.Sprintf("%s/%s", group, cName)
		}

		if s.interactionNeeded(rFields, rParams) {
			shown, err := s.replyInteraction(rCmd, rGroup, rFields, rParams, m, user, replier)
			if err != nil {
				s.replyError(cName, m, replier, err, []*common.Attachment{})
				s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
				return
			}
			if shown {
				return
			}
		} else {
			// fix string to appropriate value
			for _, f := range rFields {

				p := eParams[f.Name]
				if p == nil {
					continue
				}

				switch f.Type {
				case common.FieldTypeMultiSelect:
					v := fmt.Sprintf("%v", p)
					eParams[f.Name] = common.RemoveEmptyStrings(strings.Split(v, ","))
				}
			}
		}

		err = s.postUserCommand(cmd, m, user, replier, eParams)
		if err != nil {
			s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
			return
		}
	}
	return def
}

func (s *Slack) hideInteraction(m *slackMessageInfo, responseURL string) {
	s.client.SlackClient().PostEphemeral(m.channelID, m.userID,
		slack.MsgOptionReplaceOriginal(responseURL),
		slack.MsgOptionDeleteOriginal(responseURL),
	)
}

func (s *Slack) Post(channel string, message string, attachments []*common.Attachment, parent common.Message) error {

	channelID := channel
	threadTS := ""
	visible := true
	userID := ""

	if !utils.IsEmpty(parent) {

		threadTS = parent.ID()
		p, ok := parent.(*SlackMessage)
		if ok {
			ts := p.threadTimestamp
			if !utils.IsEmpty(ts) {
				threadTS = ts
			}
		}

		user := parent.User()
		if !utils.IsEmpty(user) {
			userID = user.ID()
			visible = parent.Visible()
		}
	}

	atts, err := s.buildAttachmentBlocks(attachments)
	if err != nil {
		return err
	}

	blocks := []slack.Block{}
	blocks = append(blocks, slack.NewSectionBlock(
		slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
		[]*slack.TextBlockObject{}, nil,
	))

	options := []slack.MsgOption{}
	options = append(options, slack.MsgOptionBlocks(blocks...), slack.MsgOptionAttachments(atts...))

	if !utils.IsEmpty(threadTS) {
		options = append(options, slack.MsgOptionTS(threadTS))
	}

	if !visible && !utils.IsEmpty(userID) {
		options = append(options, slack.MsgOptionPostEphemeral(userID))
	}

	client := s.client.SlackClient()
	_, _, err = client.PostMessage(channelID, options...)
	return err
}

func (s *Slack) interactionDefinition(cmd common.Command, group string) *slacker.InteractionDefinition {

	cName := cmd.Name()
	interactionID := s.getInteractionID(cName, group)
	def := &slacker.InteractionDefinition{
		InteractionID: interactionID,
		Type:          slack.InteractionTypeBlockActions,
	}
	def.Handler = func(ic *slacker.InteractionContext) {

		callback := ic.Callback()
		replier := ic.Response()

		m := &slackMessageInfo{
			typ:             callback.Container.Type,
			text:            "", // get this from button value
			userID:          callback.User.ID,
			channelID:       callback.Container.ChannelID,
			timestamp:       "",                          // get this from button value
			threadTimestamp: callback.Container.ThreadTs, // keep thread TS
		}

		actions := callback.ActionCallback.BlockActions
		if len(actions) == 0 {
			s.logger.Error("Slack actions are not defined.")
			s.removeReaction(m, s.options.ReactionDialog)
			return
		}

		action := actions[0]

		data, err := base64.StdEncoding.DecodeString(action.Value)
		if err != nil {
			s.removeReaction(m, s.options.ReactionDialog)
			return
		}

		value := &SlackButtonValue{}
		err = json.Unmarshal(data, value)
		if err != nil {
			s.removeReaction(m, s.options.ReactionDialog)
			return
		}

		m.timestamp = value.Timestamp // this is original message TS
		m.text = value.Text           // this is original message text

		s.hideInteraction(m, callback.ResponseURL)
		s.removeReaction(m, s.options.ReactionDialog)

		switch action.ActionID {
		case slackSubmitAction:

			user, err := s.client.SlackClient().GetUserInfo(m.userID)
			if err != nil {
				s.logger.Error("Slack couldn't get user for %s: %s", m.userID, err)
			}

			params := make(common.ExecuteParams)
			states := callback.BlockActionState
			if states != nil && len(states.Values) > 0 {

				for _, v1 := range states.Values {
					for k2, v2 := range v1 {
						name := strings.Replace(k2, fmt.Sprintf("%s-", interactionID), "", 1)

						var v interface{}
						v = v2.Value
						switch v2.Type {
						case "number_input":
							v = v2.Value
						case "datepicker":
							v = v2.SelectedDate
						case "timepicker":
							v = v2.SelectedTime
						case "static_select":
							v = v2.SelectedOption.Value
						case "multi_static_select":
							arr := []string{}
							for _, v2 := range v2.SelectedOptions {
								arr = append(arr, v2.Value)
							}
							v = arr
						case "checkboxes":
							arr := []string{}
							for _, v2 := range v2.SelectedOptions {
								arr = append(arr, v2.Value)
							}
							v = strings.Join(arr, ",")
							if utils.IsEmpty(v) {
								v = fmt.Sprintf("%v", false)
							}
						}
						params[name] = v
					}
				}
			}

			// do unwrap
			rCmd := cmd
			rParams := params
			if !utils.IsEmpty(value.Wrapper) {
				arr := strings.Split(value.Wrapper, "/")
				if len(arr) == 2 {
					rCmd = s.findCommand(arr[0], arr[1])
					prs, _, _, _ := s.findParams(false, rCmd.Name(), rCmd.Params(), m)
					rParams = common.MergeInterfaceMaps(prs, params)
				}
			}

			err = s.postUserCommand(rCmd, m, user, replier, rParams)
			if err != nil {
				s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
				return
			}

		default:
			s.addReaction(m, s.options.ReactionFailed)
		}
	}
	return def
}

func (s *Slack) jobDefinition(cmd common.Command) *slacker.JobDefinition {

	cName := cmd.Name()

	def := &slacker.JobDefinition{
		CronExpression: cmd.Schedule(),
		Name:           cName,
		Description:    cmd.Description(),
		HideHelp:       true,
	}
	def.Handler = func(cc *slacker.JobContext) {

		m := &slackMessageInfo{
			channelID: "#sre-tsv",
		}

		replier := cc.Response()

		err := s.postJobCommand(cmd, m, replier)
		if err != nil {
			s.logger.Error("Slack couldn't post from job %s: %s", cName, err)
			return
		}
	}
	return def
}

func (s *Slack) Debug(msg string, args ...any) {
	s.logger.Debug(msg, args...)
}

func (s *Slack) Info(msg string, args ...any) {
	s.logger.Info(msg, args...)
}

func (s *Slack) Warn(msg string, args ...any) {
	s.logger.Warn(msg, args...)
}

func (s *Slack) Error(msg string, args ...any) {
	s.logger.Error(msg, args...)
}

func (s *Slack) start() {

	options := []slacker.ClientOption{
		slacker.WithDebug(s.options.Debug),
		slacker.WithLogger(s),
		slacker.WithBotMode(slacker.BotModeIgnoreNone),
	}
	client := slacker.NewClient(s.options.BotToken, s.options.AppToken, options...)
	client.UnsupportedCommandHandler(s.unsupportedCommandHandler)

	s.defaultDefinition = nil
	s.helpDefinition = nil

	items := s.processors.Items()

	// add wrappers firstly
	for _, p := range items {

		pName := p.Name()
		commands := p.Commands()

		if !utils.IsEmpty(pName) {
			continue
		}

		sort.Slice(commands, func(i, j int) bool {
			return commands[i].Priority() < commands[j].Priority()
		})

		for _, c := range commands {

			if !c.Wrapper() {
				continue
			}

			schedule := c.Schedule()
			if !utils.IsEmpty(schedule) {
				continue
			}

			def := s.commandDefinition(c, "")
			client.AddCommand(def)
			if len(c.Fields(s, nil)) > 0 {
				client.AddInteraction(s.interactionDefinition(c, ""))
			}
		}
	}

	// add groups secondly
	for _, p := range items {

		pName := p.Name()
		commands := p.Commands()
		var group *slacker.CommandGroup

		if utils.IsEmpty(pName) {
			continue
		}
		group = client.AddCommandGroup(pName)

		sort.Slice(commands, func(i, j int) bool {
			return commands[i].Priority() < commands[j].Priority()
		})

		for _, c := range commands {

			if !c.Wrapper() {
				continue
			}

			schedule := c.Schedule()
			if !utils.IsEmpty(schedule) {
				continue
			}

			group.AddCommand(s.commandDefinition(c, pName))
			if len(c.Fields(s, nil)) > 0 {
				client.AddInteraction(s.interactionDefinition(c, pName))
			}
		}
	}

	// add root thirdly
	groupRoot := client.AddCommandGroup("")
	for _, p := range items {

		pName := p.Name()
		commands := p.Commands()

		if !utils.IsEmpty(pName) {
			continue
		}

		sort.Slice(commands, func(i, j int) bool {
			return commands[i].Priority() < commands[j].Priority()
		})

		for _, c := range commands {

			name := c.Name()

			if c.Wrapper() {
				continue
			}

			schedule := c.Schedule()
			if !utils.IsEmpty(schedule) {
				continue
			}

			if name == s.options.DefaultCommand {
				s.defaultDefinition = s.commandDefinition(c, "")
			} else {
				def := s.commandDefinition(c, "")
				if name == s.options.HelpCommand {
					s.helpDefinition = def
					client.Help(def)
				}
				groupRoot.AddCommand(def)
				if len(c.Fields(s, nil)) > 0 {
					client.AddInteraction(s.interactionDefinition(c, ""))
				}
			}
		}
	}

	// add jobs
	for _, p := range items {

		commands := p.Commands()

		sort.Slice(commands, func(i, j int) bool {
			return commands[i].Priority() < commands[j].Priority()
		})

		for _, c := range commands {

			schedule := c.Schedule()
			if utils.IsEmpty(schedule) {
				continue
			}
			client.AddJob(s.jobDefinition(c))
		}
	}

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
