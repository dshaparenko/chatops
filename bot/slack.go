package bot

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/slack-go/slack/socketmode"
	slacker "github.com/slack-io/slacker"
)

type SlackOptions struct {
	BotToken         string
	AppToken         string
	Debug            bool
	DefaultCommand   string
	HelpCommand      string
	GroupPermissions string
	UserPermissions  string
	Timeout          int
	PublicChannel    string

	ApprovalAllowed bool
	ApprovalMessage string

	AttachmentColor string
	ErrorColor      string

	TitleConfirmation string
	ApprovedMessage   string
	RejectedMessage   string

	ReactionDoing    string
	ReactionDone     string
	ReactionFailed   string
	ReactionDialog   string
	ReactionApproved string
	ReactionRejected string

	ButtonSubmitCaption  string
	ButtonSubmitStyle    string
	ButtonCancelCaption  string
	ButtonCancelStyle    string
	ButtonConfirmCaption string
	ButtonRejectCaption  string
	ButtonApproveCaption string
}

type SlackUser struct {
	id       string
	name     string
	timezone string
	commands []string
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
	ctx               context.Context
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

const (
	SlackButtonValueFormType     string = "form"
	SlackButtonValueApprovalType string = "approval"
)

type SlackButtonValue struct {
	Type      string
	Timestamp string
	ChannelID string
	UserID    string
	Text      string
	Command   string
	Group     string
	Params    common.ExecuteParams
	Wrapped   string
	Wrapper   string
}

type SlackPostReplier struct {
	slack *Slack
}

type slackMessageInfo struct {
	typ             string
	text            string
	userID          string
	botID           string
	channelID       string
	timestamp       string
	threadTimestamp string
	wrapped         string
	wrapper         string
	commands        []string
}

type SlackResponse struct {
	visible  bool
	original bool
	duration bool
	error    bool
}

const (
	slackAPIURL                      = "https://slack.com/api/"
	slackFilesGetUploadURLExternal   = "files.getUploadURLExternal"
	slackFilesCompleteUploadExternal = "files.completeUploadExternal"
	slackFilesSharedPublicURL        = "files.sharedPublicURL"
	slackMaxTextBlockLength          = 3000
	slackSubmitAction                = "submit"
	slackCancelAction                = "cancel"
	slackTriggerOnCharacterEntered   = "on_character_entered"
	slackTriggerOnEnterPressed       = "on_enter_pressed"
)

// SlackResponse

func (r *SlackResponse) Visible() bool {
	return r.visible
}

func (r *SlackResponse) Duration() bool {
	return r.duration
}

func (r *SlackResponse) Original() bool {
	return r.original
}

func (r *SlackResponse) Error() bool {
	return r.error
}

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

func (su *SlackUser) Commands() []string {
	return su.commands
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

func (sm *SlackMessage) ParentID() string {
	return sm.threadTimestamp
}

// Slack

func (s *Slack) Name() string {
	return "Slack"
}

func (s *Slack) prepareInputText(input, typ string) string {

	text := input
	switch typ {
	case "slash_commands":
		// /command <param1>
		text = strings.TrimSpace(text)
		items := strings.Split(text, " ")
		if len(items) > 0 {
			group, cmd := s.processors.FindCommandByAlias(items[0])
			if cmd != nil {
				groupName := cmd.Name()
				if !utils.IsEmpty(group) {
					groupName = fmt.Sprintf("%s %s", group, groupName)
				}
				text = strings.Replace(text, items[0], groupName, 1)
			}
		}
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
	return text
}

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
			f, err := s.uploadFileV1(a)
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

func (s *Slack) AddReaction(channelID, timestamp, name string) error {

	err := s.client.SlackClient().AddReaction(name, slack.NewRefToMessage(channelID, timestamp))
	if err != nil {
		s.logger.Error("Slack adding reaction error: %s", err)
		return err
	}
	return nil
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
func (s *Slack) denyGroupAccess(userID, command string, groups []slack.UserGroup) bool {

	if utils.IsEmpty(s.options.GroupPermissions) {
		return true
	}

	if s.auth == nil {
		return false
	}

	// bot itself
	if s.auth.UserID == userID {
		return false
	}

	permissions := utils.MapGetKeyValues(s.options.GroupPermissions)
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

// .*=^(help|news|app|application|catalog)$,some=^(escalate)$
func (s *Slack) denyUserAccess(userID, userName string, command string) bool {

	if utils.IsEmpty(s.options.UserPermissions) {
		return true
	}

	if s.auth == nil {
		return false
	}

	// bot itself
	if s.auth.UserID == userID {
		return false
	}

	userPermissions := utils.MapGetKeyValues(s.options.UserPermissions)
	for user, value := range userPermissions {

		reCommand, err := regexp.Compile(value)
		if err != nil {
			s.logger.Error("Slack command regex error: %s", err)
			return true
		}

		mCommand := reCommand.MatchString(command)
		if !mCommand {
			continue
		}

		reUserID, err := regexp.Compile(user)
		if err != nil {
			s.logger.Error("Slack user ID regex error: %s", err)
			return true
		}

		reUserName, err := regexp.Compile(user)
		if err != nil {
			s.logger.Error("Slack user name regex error: %s", err)
			return true
		}

		if reUserID.MatchString(userID) || reUserName.MatchString(userName) {
			return false
		}
	}
	return true
}

func (s *Slack) listUserCommands(userID string) ([]string, error) {

	commands := []string{}
	slackGroups, err := s.client.SlackClient().GetUserGroups(slack.GetUserGroupsOptionIncludeCount(true), slack.GetUserGroupsOptionIncludeUsers(true))
	if err != nil {
		s.logger.Error("Slack getting user group error: %s", err)
		return commands, err
	}

	for _, p := range s.processors.Items() {
		for _, c := range p.Commands() {
			groupName := c.Name()
			if !utils.IsEmpty(p.Name()) {
				groupName = p.Name() + "/" + groupName
			}
			if s.denyUserAccess(userID, "", groupName) && s.denyGroupAccess(userID, groupName, slackGroups) {
				continue
			}
			commands = append(commands, groupName)
		}
	}
	return commands, nil
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

func (s *Slack) findParams(wrapper bool, m *slackMessageInfo) (common.ExecuteParams, common.Command, string, common.ExecuteParams, common.Command, string) {

	ep := make(common.ExecuteParams)
	wp := make(common.ExecuteParams)

	// group command param1 param2
	// command param1 param2

	// find group, command, params

	text := s.prepareInputText(m.text, m.typ)
	delim := " "
	arr := strings.Split(text, delim)

	if len(arr) == 0 {
		return ep, nil, "", wp, nil, ""
	}

	if !wrapper {

		egr := ""
		ec := ""
		eps := ""

		if len(arr) > 0 {
			egr = strings.TrimSpace(arr[0])
		}
		if len(arr) > 1 {
			ec = strings.TrimSpace(arr[1])
		}
		if len(arr) > 2 {
			eps = strings.TrimSpace(strings.Join(arr[2:], delim))
		}

		ecm := s.processors.FindCommand(egr, ec)
		if ecm == nil {
			if len(arr) > 1 {
				eps = strings.TrimSpace(strings.Join(arr[1:], delim))
			}
			ec = egr
			egr = ""
			ecm = s.processors.FindCommand(egr, ec)
		}

		if ecm == nil {
			return ep, nil, "", wp, nil, ""
		}

		if !utils.IsEmpty(eps) {
			for _, p := range ecm.Params() {

				values, _ := s.matchParam(eps, p)
				for k, v := range values {
					ep[k] = v
				}
				if len(ep) > 0 {
					break
				}
			}
		}
		return ep, ecm, egr, wp, nil, ""
	}

	// wrappergroup wrapper group command param1 param2
	// wrappergroup wrapper command param1 param2
	// wrapper command param1 param2

	// find wrapper group, command, params

	egr := ""
	ec := ""
	eps := ""

	if len(arr) > 0 {
		egr = strings.TrimSpace(arr[0])
	}
	if len(arr) > 1 {
		ec = strings.TrimSpace(arr[1])
	}
	if len(arr) > 2 {
		eps = strings.TrimSpace(strings.Join(arr[2:], delim))
	}

	ecm := s.processors.FindCommand(egr, ec)
	if ecm == nil {
		if len(arr) > 1 {
			eps = strings.TrimSpace(strings.Join(arr[1:], delim))
		}
		ec = egr
		egr = ""
		ecm = s.processors.FindCommand(egr, ec)
	}

	if ecm == nil {
		return ep, ecm, egr, wp, nil, ""
	}

	// find wrapped group, command, params

	arr = strings.Split(eps, delim)
	wgr := ""
	wc := ""
	wps := ""

	if len(arr) > 0 {
		wgr = strings.TrimSpace(arr[0])
	}
	if len(arr) > 1 {
		wc = strings.TrimSpace(arr[1])
	}
	if len(arr) > 2 {
		wps = strings.TrimSpace(strings.Join(arr[2:], delim))
	}

	wcm := s.processors.FindCommand(wgr, wc)
	if wcm == nil {
		if len(arr) > 1 {
			wps = strings.TrimSpace(strings.Join(arr[1:], delim))
		}
		wc = wgr
		wgr = ""
		eps = wc
		wcm = s.processors.FindCommand(wgr, wc)
	}

	if wcm == nil {
		return ep, ecm, egr, wp, nil, ""
	}

	if !utils.IsEmpty(wps) {
		for _, p := range wcm.Params() {

			values, _ := s.matchParam(wps, p)
			for k, v := range values {
				wp[k] = v
			}
			if len(wp) > 0 {
				break
			}
		}
	}

	if !utils.IsEmpty(eps) {
		for _, p := range ecm.Params() {

			values, _ := s.matchParam(eps, p)
			for k, v := range values {
				ep[k] = v
			}
			if len(ep) > 0 {
				break
			}
		}
	}
	return ep, ecm, egr, wp, wcm, wgr
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

func (s *Slack) textIsCommand(text string) bool {

	prev := ""

	items := strings.Split(text, ">")
	if len(items) > 1 {
		prev = strings.TrimSpace(items[0])
	}

	items = strings.Split(prev, "<")
	if len(items) > 0 {
		prev = strings.TrimSpace(items[0])
	}

	// some mention inside the text
	return utils.IsEmpty(prev)
}

func (s *Slack) unsupportedCommandHandler(cc *slacker.CommandContext) {

	text := cc.Event().Text

	if !s.textIsCommand(text) {
		return
	}

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
	response *SlackResponse, start *time.Time, error bool) (string, error) {

	threadTS := m.threadTimestamp
	text := s.prepareInputText(m.text, m.typ)
	replyInThread := !utils.IsEmpty(threadTS)

	visible := false
	original := false
	duration := false

	if !utils.IsEmpty(response) {
		visible = response.visible
		original = response.original
		duration = response.duration
	}

	if !utils.IsEmpty(m.botID) && error {
		visible = true
	}

	atts := []slack.Attachment{}
	opts := []slacker.PostOption{}
	if error {
		eatts := []slack.Attachment{}
		eatts = append(eatts, slack.Attachment{
			Color: s.options.ErrorColor,
			Blocks: slack.Blocks{
				BlockSet: []slack.Block{
					slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
						[]*slack.TextBlockObject{}, nil),
				},
			},
		})
		opts = append(opts, slacker.SetAttachments(eatts))
		atts = append(atts, eatts...)
	} else {
		batts, err := s.buildAttachmentBlocks(attachments)
		if err != nil {
			return "", err
		}
		opts = append(opts, slacker.SetAttachments(batts))
		atts = append(atts, batts...)
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

	// default => command as text
	// dirty trick

	slackOpts := []slack.MsgOption{
		slack.MsgOptionText("", false),
		slack.MsgOptionAttachments(atts...),
		slack.MsgOptionBlocks(blocks...),
	}

	if replyInThread {
		slackOpts = append(slackOpts, slack.MsgOptionTS(threadTS))
	}

	if !visible {
		slackOpts = append(slackOpts, slack.MsgOptionPostEphemeral(m.userID))
	}

	_, timestamp, err := s.client.SlackClient().PostMessageContext(
		s.ctx,
		m.channelID,
		slackOpts...,
	)
	return timestamp, err
}

func (s *Slack) replyError(command string, m *slackMessageInfo,
	replier interface{}, err error, attachments []*common.Attachment) (string, error) {

	s.logger.Error("Slack reply error: %s", err)
	return s.reply(command, m, replier, err.Error(), attachments, nil, nil, true)
}

func (s *Slack) buildInteractionID(command, group string) string {

	if utils.IsEmpty(group) {
		return command
	}
	return fmt.Sprintf("%s-%s", command, group)
}

func (s *Slack) getInteractionGroupCommand(interactionID string) (string, string) {

	items := strings.Split(interactionID, "-")
	if len(items) == 1 {
		return items[0], ""
	}
	if len(items) == 2 {
		return items[1], items[0]
	}
	return interactionID, ""
}

func (s *Slack) buildActionID(interaction, name string) string {

	if utils.IsEmpty(name) {
		return interaction
	}
	return fmt.Sprintf("%s-%s", interaction, name)
}

func (s *Slack) fieldDependencies(name string, fields []common.Field) []common.Field {

	r := []common.Field{}
	for _, field := range fields {
		if utils.Contains(field.Dependencies, name) {
			r = append(r, field)
		}
	}
	return r
}

func (s *Slack) formBlocks(command, group, confirmation string, fields []common.Field, params common.ExecuteParams,
	m *slackMessageInfo, u *slack.User) ([]slack.Block, error) {

	blocks := []slack.Block{}

	interactionID := s.buildInteractionID(command, group)

	for _, field := range fields {

		actionID := s.buildActionID(interactionID, field.Name)

		var dac *slack.DispatchActionConfig

		deps := s.fieldDependencies(field.Name, fields)
		if len(deps) > 0 {
			dac = &slack.DispatchActionConfig{
				TriggerActionsOn: []string{slackTriggerOnEnterPressed},
			}
		}

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
			e.DispatchActionConfig = dac
			el = e
		case common.FieldTypeInteger:
			e := slack.NewNumberInputBlockElement(h, actionID, false)
			e.InitialValue = def
			e.DispatchActionConfig = dac
			el = e
		case common.FieldTypeFloat:
			e := slack.NewNumberInputBlockElement(h, actionID, true)
			e.InitialValue = def
			e.DispatchActionConfig = dac
			el = e
		case common.FieldTypeURL:
			e := slack.NewURLTextInputBlockElement(h, actionID)
			e.InitialValue = def
			e.DispatchActionConfig = dac
			//e.FocusOnLoad = field.Focus
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
		case common.FieldTypeSelect, common.FieldTypeDynamicSelect:
			options := []*slack.OptionBlockObject{}
			var dBlock *slack.OptionBlockObject
			optType := slack.OptTypeExternal
			if field.Type == common.FieldTypeSelect {
				for _, v := range field.Values {
					block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h)
					if v == def {
						dBlock = block
					}
					options = append(options, block)
				}
				optType = slack.OptTypeStatic
			}
			e := slack.NewOptionsSelectBlockElement(optType, h, actionID, options...)
			if dBlock != nil {
				e.InitialOption = dBlock
			}
			el = e
		case common.FieldTypeMultiSelect, common.FieldTypeDynamicMultiSelect:
			options := []*slack.OptionBlockObject{}
			dBlocks := []*slack.OptionBlockObject{}
			optType := slack.MultiOptTypeExternal
			if field.Type == common.FieldTypeMultiSelect {
				arr := common.RemoveEmptyStrings(strings.Split(def, ","))
				for _, v := range field.Values {
					block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h)
					if utils.Contains(arr, v) {
						dBlocks = append(dBlocks, block)
					}
					options = append(options, block)
				}
				optType = slack.MultiOptTypeStatic
			}
			e := slack.NewOptionsMultiSelectBlockElement(optType, h, actionID, options...)
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
			e.DispatchActionConfig = dac
			el = e
		}

		b = slack.NewInputBlock("", l, nil, el)
		if b != nil {
			b.DispatchAction = dac != nil
			b.Optional = !field.Required
			blocks = append(blocks, b)
		}
	}

	if len(blocks) == 0 {
		return blocks, nil
	}

	// pass message timestamp & text to each button
	value := &SlackButtonValue{
		Type:      SlackButtonValueFormType,
		ChannelID: m.channelID,
		UserID:    m.userID,
		Command:   command,
		Group:     group,
		Params:    params,
		Timestamp: m.timestamp,
		Text:      m.text,
		Wrapped:   m.wrapped,
		Wrapper:   m.wrapper,
	}
	data, err := json.Marshal(value)
	if err != nil {
		return blocks, err
	}
	sv := base64.StdEncoding.EncodeToString(data)

	submit := slack.NewButtonBlockElement(slackSubmitAction, sv, slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonSubmitCaption, false, false))
	submit.Style = slack.Style(s.options.ButtonSubmitStyle)

	if !utils.IsEmpty(confirmation) {
		submit.Confirm = slack.NewConfirmationBlockObject(
			slack.NewTextBlockObject(slack.PlainTextType, s.options.TitleConfirmation, false, false),
			slack.NewTextBlockObject(slack.PlainTextType, confirmation, false, false),
			slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonConfirmCaption, false, false),
			slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonRejectCaption, false, false),
		)
	}

	cancel := slack.NewButtonBlockElement(slackCancelAction, sv, slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonCancelCaption, false, false))
	cancel.Style = slack.Style(s.options.ButtonCancelStyle)

	ab := slack.NewActionBlock(interactionID, submit, cancel)
	blocks = append(blocks, ab)

	return blocks, nil
}

func (s *Slack) replyForm(command, group, confirmation string, fields []common.Field, params common.ExecuteParams,
	m *slackMessageInfo, u *slack.User, replier *slacker.ResponseReplier) (bool, error) {

	threadTS := m.threadTimestamp
	opts := []slacker.PostOption{}
	replyInThread := !utils.IsEmpty(threadTS)
	if replyInThread {
		opts = append(opts, slacker.SetThreadTS(threadTS))
	}

	if utils.IsEmpty(m.botID) {
		opts = append(opts, slacker.SetEphemeral(m.userID))
	}

	blocks, err := s.formBlocks(command, group, confirmation, fields, params, m, u)
	if err != nil {
		return false, err
	}

	s.addReaction(m, s.options.ReactionDialog)
	_, err = replier.PostBlocks(m.channelID, blocks, opts...)
	if err != nil {
		s.removeReaction(m, s.options.ReactionDialog)
		return false, err
	}
	return true, nil
}

func (s *Slack) askApproval(approval common.Approval, command, group string,
	m *slackMessageInfo, u *slack.User, params common.ExecuteParams, replier *slacker.ResponseReplier) (bool, error) {

	opts := []slacker.PostOption{}

	blocks := []slack.Block{}
	interactionID := s.buildInteractionID(command, group)

	user := &SlackUser{
		id: m.userID,
	}
	if u != nil {
		user.name = u.Name
		user.timezone = u.TZ
	}

	channel := &SlackChannel{
		id: m.channelID,
	}

	msg := &SlackMessage{
		id:              m.timestamp,
		user:            user,
		threadTimestamp: m.threadTimestamp,
		channel:         channel,
	}

	message := approval.Message(s, msg, params)
	if utils.IsEmpty(message) {
		message = s.options.ApprovalMessage
	}

	blocks = append(blocks, slack.NewSectionBlock(
		slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
		[]*slack.TextBlockObject{}, nil,
	))

	// pass message timestamp & text to each button
	value := &SlackButtonValue{
		Type:      SlackButtonValueApprovalType,
		ChannelID: m.channelID,
		UserID:    m.userID,
		Command:   command,
		Group:     group,
		Params:    params,
		Timestamp: m.timestamp,
		Text:      m.text,
		Wrapped:   m.wrapped,
		Wrapper:   m.wrapper,
	}
	data, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	sv := base64.StdEncoding.EncodeToString(data)

	submit := slack.NewButtonBlockElement(slackSubmitAction, sv, slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonApproveCaption, false, false))
	submit.Style = slack.Style(s.options.ButtonSubmitStyle)

	cancel := slack.NewButtonBlockElement(slackCancelAction, sv, slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonRejectCaption, false, false))
	cancel.Style = slack.Style(s.options.ButtonCancelStyle)

	ab := slack.NewActionBlock(interactionID, submit, cancel)
	blocks = append(blocks, ab)

	s.addReaction(m, s.options.ReactionDialog)
	_, err = replier.PostBlocks(approval.Channel(), blocks, opts...)
	if err != nil {
		s.removeReaction(m, s.options.ReactionDialog)
		return false, err
	}
	return true, nil
}

func (s *Slack) postUserCommand(cmd common.Command, m *slackMessageInfo, u *slack.User,
	replier interface{}, params common.ExecuteParams, response common.Response, reaction bool) error {

	//  should check parent if its visible and its thread message

	cName := cmd.Name()

	commands := m.commands
	if len(commands) == 0 {
		cmds, err := s.listUserCommands(m.userID)
		if err != nil {
			s.logger.Error("Slack couldn't get commands for %s: %s", m.userID, err)
			return err
		}
		commands = cmds
	}

	user := &SlackUser{
		id:       m.userID,
		commands: commands,
	}
	if u != nil {
		user.name = u.Name
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

	if reaction {
		s.addReaction(m, s.options.ReactionDoing)
	}

	start := time.Now()
	executor, message, attachments, err := cmd.Execute(s, msg1, params)
	if err != nil {
		if reaction {
			s.replyError(cName, m, replier, err, attachments)
			s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
		}
		return err
	}

	r := &SlackResponse{}
	eResponse := executor.Response()
	if !utils.IsEmpty(eResponse) {

		r.visible = eResponse.Visible()
		r.error = eResponse.Error()
		r.duration = eResponse.Duration()
		r.original = eResponse.Original()

	} else if !utils.IsEmpty(response) {
		r.visible = response.Visible()
		r.error = response.Error()
		r.duration = response.Duration()
		r.original = response.Original()
	}

	ts := ""
	if !utils.IsEmpty(message) {

		ts, err = s.reply(cName, m, replier, message, attachments, r, &start, r.error)
		if err != nil {
			if reaction {
				s.replyError(cName, m, replier, err, attachments)
				s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
			}
			return err
		}
	}

	if reaction {
		if r.error {
			s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
		} else {
			s.addRemoveReactions(m, s.options.ReactionDone, s.options.ReactionDoing)
		}
	}

	ts2 := m.threadTimestamp
	if r.visible {
		ts2 = ts
	}
	msg2 := &SlackMessage{
		id:              ts,
		visible:         r.visible,
		user:            user,
		threadTimestamp: ts2,
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

	r := &SlackResponse{}
	response := executor.Response()
	if !utils.IsEmpty(response) {
		r.visible = response.Visible()
		r.error = response.Error()
	}

	ts, err := s.reply(cName, m, replier, message, attachments, r, &start, r.error)
	if err != nil {
		return err
	}

	msg2 := &SlackMessage{
		id:              ts,
		visible:         r.visible,
		threadTimestamp: m.threadTimestamp,
		channel:         channel,
	}

	return executor.After(msg2)
}

func (s *Slack) formNeeded(confirmation string, fields []common.Field, params map[string]interface{}) bool {

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
	return len(required) > len(arr) || !utils.IsEmpty(confirmation)
}

func (s *Slack) approvalNeeded(approval common.Approval) bool {

	if approval == nil {
		return false
	}
	return !utils.IsEmpty(approval.Channel())
}

func (s *Slack) getFieldsByType(cmd common.Command, types []string) []string {

	r := []string{}

	fields := cmd.Fields(s, nil, nil, nil, false)
	if len(fields) == 0 {
		return r
	}

	for _, field := range fields {

		if utils.Contains(types, string(field.Type)) {
			r = append(r, field.Name)
		}
	}
	return r
}

func (s *Slack) Command(channel, text string, user common.User, parent common.Message, response common.Response) error {

	if utils.IsEmpty(user) {
		s.logger.Debug("Slack command has no user for text: %s", text)
		return nil
	}

	u := s.getSlackUser(user.ID(), "")

	m := &slackMessageInfo{
		typ:       "message",
		text:      text,
		userID:    u.ID,
		channelID: channel,
	}

	if !utils.IsEmpty(parent) {
		m.threadTimestamp = parent.ParentID()
	}

	params, cmd, group, _, _, _ := s.findParams(false, m)
	if cmd == nil {
		s.logger.Debug("Slack command not found for text: %s", text)
		return nil
	}

	commands, err := s.listUserCommands(m.userID)
	if err != nil {
		s.logger.Error("Slack couldn't get commands for %s: %s", m.userID, err)
		return err
	}
	m.commands = commands

	groupName := cmd.Name()
	if !utils.IsEmpty(group) {
		groupName = fmt.Sprintf("%s/%s", group, groupName)
	}

	if !utils.Contains(commands, groupName) {
		s.logger.Debug("Slack command user %s is not permitted to execute %s", m.userID, groupName)
		return nil
	}

	fields := cmd.Fields(s, parent, params, nil, true)
	if s.formNeeded(cmd.Confirmation(), fields, params) {
		s.logger.Debug("Slack command %s has no support for interaction mode", groupName)
		return nil
	}

	err = s.postUserCommand(cmd, m, u, nil, params, response, false)
	if err != nil {
		s.logger.Error("Slack command %s couldn't post from %s: %s", groupName, m.userID, err)
		return err
	}

	return nil
}

func (s *Slack) getSlackUser(userID, botID string) *slack.User {

	var user *slack.User

	if !utils.IsEmpty(userID) {

		u, err := s.client.SlackClient().GetUserInfo(userID)
		if err != nil {
			s.logger.Error("Slack couldn't get user for %s: %s", userID, err)
		}
		if u != nil {
			user = u
		}
	} else if !utils.IsEmpty(botID) {

		bot, err := s.client.SlackClient().GetBotInfo(slack.GetBotInfoParameters{Bot: botID})
		if err != nil {
			s.logger.Error("Slack couldn't get bot for %s: %s", botID, err)
		}
		if bot != nil {
			u, err := s.client.SlackClient().GetUserInfo(bot.UserID)
			if err != nil {
				s.logger.Error("Slack couldn't get user for %s: %s", bot.UserID, err)
			}
			if u != nil {
				user = u
			}
		}
	}
	return user
}

func (s *Slack) commandDefinition(cmd common.Command, group string) *slacker.CommandDefinition {

	def := &slacker.CommandDefinition{
		Command:     cmd.Name(),
		Aliases:     cmd.Aliases(),
		Description: cmd.Description(),
		HideHelp:    true,
	}
	def.Handler = func(cc *slacker.CommandContext) {

		event := cc.Event()

		if !s.textIsCommand(event.Text) {
			return
		}

		if utils.IsEmpty(event.UserID) && utils.IsEmpty(event.BotID) {
			s.logger.Error("Slack has no user nor bot ID")
		}

		userID := ""

		user := s.getSlackUser(event.UserID, event.BotID)

		if user != nil {
			userID = user.ID
		}

		if utils.IsEmpty(userID) {
			s.logger.Error("Slack couldn't process command from unknown user")
			return
		}

		if s.auth != nil && s.auth.UserID == userID {
			return
		}

		m := &slackMessageInfo{
			typ:             event.Type,
			text:            event.Text,
			userID:          userID,
			botID:           event.BotID,
			channelID:       event.ChannelID,
			timestamp:       event.TimeStamp,
			threadTimestamp: event.ThreadTimeStamp,
		}

		replier := cc.Response()

		if def == s.defaultDefinition {
			err := s.postUserCommand(cmd, m, user, replier, nil, nil, true)
			if err != nil {
				s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
			}
			return
		}

		wrapper := cmd.Wrapper()
		eParams, eCmd, eGroup, wrappedParams, wrappedCmd, wrappedGroup := s.findParams(wrapper, m)

		if eCmd == nil {
			eCmd = cmd
			eGroup = group
		}

		cName := eCmd.Name()
		group = eGroup

		text := s.prepareInputText(event.Text, event.Type)
		s.updateCounters(group, cName, text, userID)

		groupName := cName
		if !utils.IsEmpty(group) {
			groupName = fmt.Sprintf("%s/%s", group, cName)
		}

		if eCmd.Permissions() {

			commands, err := s.listUserCommands(userID)
			if err != nil {
				s.logger.Error("Slack couldn't get commands for %s: %s", userID, err)
				return
			}
			m.commands = commands

			if def != s.defaultDefinition {
				if !utils.Contains(commands, groupName) {
					s.logger.Error("Slack user %s is not permitted to execute %s", userID, groupName)
					s.unsupportedCommandHandler(cc)
					return
				}
			}
		}

		mChannel := &SlackChannel{
			id: m.channelID,
		}

		mUser := &SlackUser{
			id:       m.userID,
			name:     user.Name,
			timezone: user.TZ,
			commands: []string{groupName},
		}

		msg := &SlackMessage{
			id:              m.timestamp,
			user:            mUser,
			threadTimestamp: m.threadTimestamp,
			channel:         mChannel,
		}

		rCommand := cName
		eCommand := ""

		if eCmd != nil {
			eCommand = eCmd.Name()
			if !utils.IsEmpty(eCommand) {
				cmd = eCmd
				rCommand = eCommand
			}
		}

		rGroup := group
		if !utils.IsEmpty(eGroup) {
			rGroup = eGroup
		}

		rFields := cmd.Fields(s, msg, eParams, nil, false)
		rParams := eParams

		confirmation := cmd.Confirmation()

		approvalCmd := cmd
		approvalCommand := rCommand
		approvalGroup := rGroup
		approvalParams := rParams

		if wrapper {

			rCommand = ""
			if wrappedCmd != nil {
				rCommand = wrappedCmd.Name()
			} else {
				return
			}
			rGroup = wrappedGroup

			wrapperGroupName := rCommand
			if utils.IsEmpty(wrapperGroupName) {
				wrapperGroupName = rGroup
			}
			if !utils.IsEmpty(rGroup) && !utils.IsEmpty(rCommand) {
				wrapperGroupName = fmt.Sprintf("%s/%s", rGroup, rCommand)
			}

			if wrappedCmd.Permissions() {

				commands, err := s.listUserCommands(userID)
				if err != nil {
					s.logger.Error("Slack couldn't get commands for %s: %s", userID, err)
					return
				}
				m.commands = commands

				if def != s.defaultDefinition {
					if !utils.Contains(commands, wrapperGroupName) {
						s.logger.Debug("Slack user %s is not permitted to execute %s", m.userID, wrapperGroupName)
						s.unsupportedCommandHandler(cc)
						return
					}
				}
			}

			rFields = wrappedCmd.Fields(s, msg, rParams, nil, false)
			confirmation = wrappedCmd.Confirmation()

			rParams = wrappedParams
			m.wrapped = fmt.Sprintf("%s/%s", rGroup, rCommand)
			m.wrapper = fmt.Sprintf("%s/%s", eGroup, eCommand)

			approvalCmd = wrappedCmd
			approvalCommand = rCommand
			approvalGroup = rGroup
			approvalParams = rParams
		}

		if s.formNeeded(confirmation, rFields, rParams) && user != nil {
			shown, err := s.replyForm(rCommand, rGroup, confirmation, rFields, rParams, m, user, replier)
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

				p := rParams[f.Name]
				if p == nil {
					continue
				}

				switch f.Type {
				case common.FieldTypeMultiSelect, common.FieldTypeDynamicMultiSelect:
					v := fmt.Sprintf("%v", p)
					rParams[f.Name] = common.RemoveEmptyStrings(strings.Split(v, ","))
				}
			}
		}

		approval := approvalCmd.Approval()
		if s.approvalNeeded(approval) {
			shown, err := s.askApproval(approval, approvalCommand, approvalGroup, m, user, approvalParams, replier)
			if err != nil {
				s.replyError(cName, m, replier, err, []*common.Attachment{})
				s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
				return
			}
			if shown {
				return
			}
		}

		rParams = common.MergeInterfaceMaps(eParams, rParams)

		err := s.postUserCommand(cmd, m, user, replier, rParams, nil, true)
		if err != nil {
			s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
			return
		}
	}
	return def
}

func (s *Slack) removeMessage(m *slackMessageInfo, responseURL string) {
	s.client.SlackClient().PostEphemeral(m.channelID, m.userID,
		slack.MsgOptionReplaceOriginal(responseURL),
		slack.MsgOptionDeleteOriginal(responseURL),
	)
}

func (s *Slack) replaceMessage(m *slackMessageInfo, responseURL string, blocks []slack.Block) {

	s.client.SlackClient().PostEphemeral(m.channelID, m.userID,
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionReplaceOriginal(responseURL),
	)
}

func (s *Slack) replaceApprovalMessage(m *slackMessageInfo, responseURL string, mblocks []slack.Block, message string) {

	blocks := []slack.Block{}
	for _, block := range mblocks {
		if block.BlockType() != slack.MBTAction {
			blocks = append(blocks, block)
		}
	}

	if !utils.IsEmpty(message) {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
			[]*slack.TextBlockObject{}, nil,
		))
	}
	s.replaceMessage(m, responseURL, blocks)
}

/*func (s *Slack) replyInThread(m *slackMessageInfo, message string) {

	blocks := []slack.Block{}
	blocks = append(blocks, slack.NewSectionBlock(
		slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
		[]*slack.TextBlockObject{}, nil,
	))

	s.client.SlackClient().PostMessage(m.channelID,
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionTS(m.timestamp),
	)
}*/

func (s *Slack) Post(channel string, message string, attachments []*common.Attachment, user common.User, parent common.Message, response common.Response) error {

	channelID := channel
	threadTS := ""
	visible := true
	userID := ""

	if !utils.IsEmpty(parent) {
		threadTS = parent.ParentID()
	}

	if !utils.IsEmpty(user) {
		userID = user.ID()
	}

	if !utils.IsEmpty(response) {
		visible = response.Visible()
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
	options = append(options, slack.MsgOptionDisableLinkUnfurl())

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

func (s *Slack) formButtonCallbackHandler(m *slackMessageInfo, action *slack.BlockAction, ctx *slacker.InteractionContext) {

	callback := ctx.Callback()
	replier := ctx.Response()

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

	cmd := s.processors.FindCommand(value.Group, value.Command)
	if cmd == nil {
		s.logger.Error("Slack command is missed.")
		s.removeReaction(m, s.options.ReactionDialog)
		return
	}

	params := value.Params

	interactionID := s.buildInteractionID(value.Command, value.Group)

	if action.ActionID == slackSubmitAction {

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
					case "static_select", "external_select":
						v = v2.SelectedOption.Value
					case "multi_static_select", "multi_external_select":
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
	}

	switch value.Type {
	case SlackButtonValueFormType:

		m.userID = value.UserID
		m.channelID = value.ChannelID
		m.timestamp = value.Timestamp
		m.text = value.Text
		m.wrapped = value.Wrapped
		m.wrapper = value.Wrapper

		approval := cmd.Approval()
		if action.ActionID == slackSubmitAction && s.approvalNeeded(approval) {

			shown, err := s.askApproval(approval, value.Command, value.Group, m, &callback.User, params, replier)
			if err != nil {
				s.replyError(value.Command, m, replier, err, []*common.Attachment{})
				s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
				return
			}
			if shown {
				s.removeMessage(m, callback.ResponseURL)
				return
			}
		}
		s.removeMessage(m, callback.ResponseURL)

	case SlackButtonValueApprovalType:

		if !s.options.ApprovalAllowed {
			if callback.User.ID == value.UserID {
				s.logger.Error("Slack same user cannot approve its action.")
				return
			}
		}

		// this is approval message TS
		m.timestamp = callback.Container.MessageTs

		message := ""
		reaction := common.IfDef(action.ActionID == slackSubmitAction, s.options.ReactionApproved, s.options.ReactionRejected)
		mdef := common.IfDef(action.ActionID == slackSubmitAction, s.options.ApprovedMessage, s.options.RejectedMessage)
		if !utils.IsEmpty(mdef) {
			user := fmt.Sprintf("@%s", callback.User.Name)
			message = fmt.Sprintf(mdef.(string), user, time.Now().Format("15:04:05"))
			message = fmt.Sprintf(":%s: %s", reaction, message)
		}
		s.replaceApprovalMessage(m, callback.ResponseURL, callback.Message.Blocks.BlockSet, message)

		// set original message TS & text
		m.userID = value.UserID
		m.channelID = value.ChannelID
		m.timestamp = value.Timestamp
		m.text = value.Text
		m.threadTimestamp = value.Timestamp
	}

	s.removeReaction(m, s.options.ReactionDialog)

	switch action.ActionID {
	case slackSubmitAction:

		// do unwrap

		response := &SlackResponse{}

		responseCmd := cmd.Response()
		if !utils.IsEmpty(responseCmd) {
			response.visible = responseCmd.Visible()
			response.duration = responseCmd.Duration()
			response.original = responseCmd.Original()
			response.error = responseCmd.Error()
		}

		if !utils.IsEmpty(value.Wrapper) {
			arr := strings.Split(value.Wrapper, "/")
			if len(arr) == 2 {
				cmd = s.processors.FindCommand(arr[0], arr[1])

				responseCmd := cmd.Response()
				if !utils.IsEmpty(responseCmd) {
					response.visible = responseCmd.Visible()
					response.duration = responseCmd.Duration()
					response.original = responseCmd.Original()
					response.error = responseCmd.Error()
				}
			}
		}

		rParams := params
		if !utils.IsEmpty(value.Wrapped) {
			arr := strings.Split(value.Wrapped, "/")
			if len(arr) == 2 {
				eParams, _, _, _, _, _ := s.findParams(!utils.IsEmpty(value.Wrapper), m)
				rParams = common.MergeInterfaceMaps(rParams, eParams)
			}
		}

		err = s.postUserCommand(cmd, m, &callback.User, replier, rParams, response, true)
		if err != nil {
			s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
			return
		}

	default:
		s.addReaction(m, s.options.ReactionFailed)
	}
}

func (s *Slack) formCallbackHandler(ctx *slacker.InteractionContext) {

	callback := ctx.Callback()

	m := &slackMessageInfo{
		typ:             callback.Container.Type,
		text:            "", // get this from button value
		userID:          callback.User.ID,
		botID:           "",
		channelID:       callback.Container.ChannelID,
		timestamp:       callback.Container.MessageTs,
		threadTimestamp: callback.Container.ThreadTs,
	}

	actions := callback.ActionCallback.BlockActions
	if len(actions) == 0 {
		s.logger.Error("Slack actions are not defined.")
		s.removeReaction(m, s.options.ReactionDialog)
		return
	}

	action := actions[0]
	if utils.Contains([]string{slackSubmitAction, slackCancelAction}, action.ActionID) {
		s.formButtonCallbackHandler(m, action, ctx)
		return
	}

	// update form according to the action and dependencies

	cmd, group, name := s.getCommandGroupField(action.ActionID)
	if cmd == nil {
		return
	}
	command := cmd.Name()

	user := &SlackUser{
		id: m.userID,
	}

	channel := &SlackChannel{
		id: m.channelID,
	}

	msg := &SlackMessage{
		id:              m.timestamp,
		visible:         !callback.Container.IsEphemeral,
		user:            user,
		threadTimestamp: m.threadTimestamp,
		channel:         channel,
	}

	// find all fields that depend on name
	deps := []string{}

	allFields := cmd.Fields(s, msg, nil, nil, false)
	for _, field := range allFields {
		if utils.Contains(field.Dependencies, name) {
			deps = append(deps, field.Name)
		}
	}

	if len(deps) == 0 {
		return
	}

	params := make(common.ExecuteParams)
	params[name] = action.Value

	// get dependent fields with default values and set params
	depFields := cmd.Fields(s, msg, params, deps, true)
	for _, field := range depFields {
		params[field.Name] = field.Default
	}

	confirmation := cmd.Confirmation()
	u := s.getSlackUser(m.userID, m.botID)

	blocks, err := s.formBlocks(command, group, confirmation, allFields, params, m, u)
	if err != nil {
		s.logger.Error("Slack couldn't generate form blocks, error: %s", err)
		return
	}

	s.replaceMessage(m, callback.ResponseURL, blocks)
}

func (s *Slack) formCallbackDefinition(name, group string) *slacker.InteractionDefinition {

	cName := name
	interactionID := s.buildInteractionID(cName, group)
	def := &slacker.InteractionDefinition{
		InteractionID: interactionID,
		Type:          slack.InteractionTypeBlockActions,
	}
	def.Handler = func(ctx *slacker.InteractionContext, req *socketmode.Request) {
		s.formCallbackHandler(ctx)
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

		m := &slackMessageInfo{}
		if !utils.IsEmpty(s.options.PublicChannel) {
			m.channelID = s.options.PublicChannel
		}
		if !utils.IsEmpty(cmd.Channel()) {
			m.channelID = cmd.Channel()
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

func (s *Slack) getCommandGroupField(ident string) (common.Command, string, string) {

	if utils.IsEmpty(ident) {
		return nil, "", ""
	}

	delim := "-"
	arr := strings.Split(ident, delim)
	if len(arr) < 1 {
		return nil, "", ""
	}

	c := ""
	g := ""
	f := ""

	if len(arr) > 0 {
		c = strings.TrimSpace(arr[0])
	}
	if len(arr) > 1 {
		g = strings.TrimSpace(arr[1])
	}
	if len(arr) > 2 {
		f = strings.TrimSpace(arr[2])
	}

	cmd := s.processors.FindCommand(g, c)
	if cmd == nil {
		if len(arr) > 1 {
			f = strings.TrimSpace(strings.Join(arr[1:], delim))
		}
		g = ""
		cmd = s.processors.FindCommand(g, c)
	}
	return cmd, g, f
}

func (s *Slack) formSuggestionHandler(ctx *slacker.InteractionContext, req *socketmode.Request) {

	callback := ctx.Callback()

	if utils.IsEmpty(callback.Value) {
		return
	}

	cmd, _, name := s.getCommandGroupField(callback.ActionID)
	if cmd == nil {
		return
	}

	user := &SlackUser{
		id: callback.User.ID,
	}

	channel := &SlackChannel{
		id: callback.Container.ChannelID,
	}

	msg := &SlackMessage{
		id:              callback.Container.MessageTs,
		visible:         !callback.Container.IsEphemeral,
		user:            user,
		threadTimestamp: callback.Container.ThreadTs,
		channel:         channel,
	}

	fields := cmd.Fields(s, msg, nil, []string{name}, true)
	var field *common.Field

	for _, f := range fields {
		if f.Name == name {
			field = &f
			break
		}
	}

	if field == nil {
		return
	}

	options := []*slack.OptionBlockObject{}
	value := strings.ToLower(callback.Value)

	for _, v := range field.Values {

		vl := strings.ToLower(v)
		if strings.Contains(vl, value) {

			var h *slack.TextBlockObject
			if !utils.IsEmpty(field.Hint) {
				h = slack.NewTextBlockObject(slack.PlainTextType, field.Hint, false, false)
			}

			options = append(options,
				slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h))
		}
	}

	if len(options) == 0 {
		return
	}

	resposne := slack.OptionsResponse{
		Options: options,
	}

	res := socketmode.Response{
		EnvelopeID: req.EnvelopeID,
		Payload:    resposne,
	}

	err := s.client.SocketModeClient().SendCtx(s.ctx, res)
	if err != nil {
		s.logger.Error(err)
		return
	}
}

func (s *Slack) unsupportedInteractionHandler(ctx *slacker.InteractionContext, req *socketmode.Request) {

	callback := ctx.Callback()

	switch callback.Type {
	case slack.InteractionTypeBlockActions:
		s.formCallbackHandler(ctx)
	case slack.InteractionTypeBlockSuggestion:
		s.formSuggestionHandler(ctx, req)
	}
}

func (s *Slack) unsupportedEventnHandler(event socketmode.Event) {

	switch event.Type {
	default:
		s.logger.Debug("Slack unsupported event type: %s", event.Type)
	}
}

func (s *Slack) start() {

	options := []slacker.ClientOption{
		slacker.WithDebug(s.options.Debug),
		slacker.WithLogger(s),
		slacker.WithBotMode(slacker.BotModeIgnoreApp),
	}
	client := slacker.NewClient(s.options.BotToken, s.options.AppToken, options...)
	client.UnsupportedCommandHandler(s.unsupportedCommandHandler)
	client.UnsupportedInteractionHandler(s.unsupportedInteractionHandler)
	client.UnsupportedEventHandler(s.unsupportedEventnHandler)

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

			def := s.commandDefinition(c, "")
			client.AddCommand(def)
			if len(c.Fields(s, nil, nil, nil, false)) > 0 {
				client.AddInteraction(s.formCallbackDefinition(c.Name(), ""))
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

			if c.Wrapper() {
				continue
			}

			group.AddCommand(s.commandDefinition(c, pName))
			if len(c.Fields(s, nil, nil, nil, false)) > 0 {
				client.AddInteraction(s.formCallbackDefinition(c.Name(), pName))
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

			if name == s.options.DefaultCommand {
				s.defaultDefinition = s.commandDefinition(c, "")
			} else {
				def := s.commandDefinition(c, "")
				if name == s.options.HelpCommand {
					s.helpDefinition = def
					client.Help(def)
				}
				groupRoot.AddCommand(def)
				if len(c.Fields(s, nil, nil, nil, false)) > 0 {
					client.AddInteraction(s.formCallbackDefinition(c.Name(), ""))
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

	s.ctx = ctx

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
