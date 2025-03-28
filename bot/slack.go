package bot

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"github.com/jellydator/ttlcache/v3"
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

	ApprovalAllowed     bool
	ApprovalReply       string
	ApprovalReasons     string
	ApprovalDescription string

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

	CacheTTL        string
	MaxQueryOptions int
	MinQueryLength  int
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
	id       string
	visible  bool
	threadTS string
	user     *SlackUser
	channel  *SlackChannel
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
	buttons           *ttlcache.Cache[string, *SlackButton]
	fields            *ttlcache.Cache[string, common.ExecuteParams]
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

type SlackButton struct {
	Type      string
	Timestamp string
	ThreadTS  string
	ChannelID string
	UserID    string
	Text      string
	Command   string
	Group     string
	Params    common.ExecuteParams
	Wrapped   string
	Wrapper   string
}

type slackMessageInfo struct {
	typ       string
	text      string
	userID    string
	botID     string
	channelID string
	timestamp string
	threadTS  string
	wrapped   string
	wrapper   string
	commands  []string
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
	slackTriggerOnCharacterEntered   = "on_character_entered"
	slackTriggerOnEnterPressed       = "on_enter_pressed"
)

const (
	slackSubmitAction               = "submit"
	slackCancelAction               = "cancel"
	slackButtonFormType             = "form"
	slackButtonApprovalType         = "approval"
	slackApprovalReasons            = "approval-reasons"
	slackApprovalDescription        = "approval-description"
	slackApprovalReasonsCaption     = "Reasons"
	slackApprovalDescriptionCaption = "Description"
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
	return sm.threadTS
}

func (sm *SlackMessage) SetParentID(threadTS string) {
	sm.threadTS = threadTS
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

func (s *Slack) RemoveReaction(channelID, timestamp, name string) error {

	err := s.client.SlackClient().RemoveReaction(name, slack.NewRefToMessage(channelID, timestamp))
	if err != nil {
		s.logger.Error("Slack removing reaction error: %s", err)
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

func (s *Slack) listUserCommands(userID string, groups []slack.UserGroup) ([]string, error) {

	commands := []string{}

	for _, p := range s.processors.Items() {
		for _, c := range p.Commands() {
			groupName := c.Name()
			if !utils.IsEmpty(p.Name()) {
				groupName = p.Name() + "/" + groupName
			}
			if s.denyUserAccess(userID, "", groupName) && s.denyGroupAccess(userID, groupName, groups) {
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

func (s *Slack) DeleteMessage(channel, ID string) error {

	_, _, err := s.client.SlackClient().DeleteMessage(channel, ID)

	if err != nil {
		s.logger.Error("Failed to delete message: ", err)
		return err
	}

	s.logger.Info("Message deleted successfully")
	return nil
}

func (s *Slack) ReadMessage(channel, ID string) (string, error) {

	params := &slack.GetConversationHistoryParameters{
		ChannelID: channel,
		Latest:    ID,
		Limit:     1,
		Inclusive: true,
	}

	r, err := s.client.SlackClient().GetConversationHistory(params)

	if err != nil {
		s.logger.Error("Failed to get message: %s", err)
		return "", err
	}

	if len(r.Messages) == 0 {
		err := fmt.Errorf("message not found")
		s.logger.Error("Failed to get message: %s", err)
		return "", err
	}

	return r.Messages[0].Text, nil
}

func (s *Slack) UpdateMessage(channel, ID, message string) error {

	_, _, _, err := s.client.SlackClient().UpdateMessage(channel, ID, slack.MsgOptionText(message, false))
	if err != nil {
		s.logger.Error("Failed to update message: ", err)
		return err
	}
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

func (s *Slack) getChannelAndTimestamp(channel string, m *slackMessageInfo) (string, string, string) {

	mThreadTS := ""
	mTimestamp := ""
	mChannel := ""
	if m != nil {
		mChannel = m.channelID
		mTimestamp = m.timestamp
		mThreadTS = m.threadTS
	}

	if !utils.IsEmpty(channel) {
		if mChannel != channel {
			mChannel = channel
			mTimestamp = ""
			mThreadTS = ""
		}
	}

	return mChannel, mTimestamp, mThreadTS
}

func (s *Slack) reply(command string, m *slackMessageInfo,
	replier interface{}, message, channel string, attachments []*common.Attachment,
	response *SlackResponse, start *time.Time, error bool) (string, error) {

	mChannel, _, mThreadTS := s.getChannelAndTimestamp(channel, m)

	text := s.prepareInputText(m.text, m.typ)
	replyInThread := !utils.IsEmpty(mThreadTS)

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
		opts = append(opts, slacker.SetThreadTS(mThreadTS))
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
		ts, err := rr.PostBlocks(mChannel, blocks, opts...)
		if err != nil {
			return "", err
		}
		return ts, nil
	}

	// ResponseWriter => jobs
	rw, ok := replier.(*slacker.ResponseWriter)
	if ok {
		ts, err := rw.PostBlocks(mChannel, blocks, opts...)
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
		slackOpts = append(slackOpts, slack.MsgOptionTS(mThreadTS))
	}

	if !visible {
		slackOpts = append(slackOpts, slack.MsgOptionPostEphemeral(m.userID))
	}

	_, timestamp, err := s.client.SlackClient().PostMessageContext(
		s.ctx,
		mChannel,
		slackOpts...,
	)
	return timestamp, err
}

func (s *Slack) replyError(command string, m *slackMessageInfo,
	replier interface{}, err error, channel string, attachments []*common.Attachment) (string, error) {

	s.logger.Error("Slack reply error: %s", err)
	return s.reply(command, m, replier, err.Error(), channel, attachments, nil, nil, true)
}

func (s *Slack) buildInteractionID(command, group string) string {

	if utils.IsEmpty(group) {
		return command
	}
	return fmt.Sprintf("%s/%s", command, group)
}

func (s *Slack) buildActionID(interaction, name string) string {

	if utils.IsEmpty(name) {
		return interaction
	}
	return fmt.Sprintf("%s-%s", interaction, name)
}

func (s *Slack) getActionID(ident string) (string, string) {

	if utils.IsEmpty(ident) {
		return "", ""
	}
	arr := strings.SplitN(ident, "-", 2)
	if len(arr) < 2 && len(arr) > 0 {
		return arr[0], ""
	}
	return arr[0], arr[1]
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

func (s *Slack) parseArrayValues(sarr string) []string {

	arr := common.RemoveEmptyStrings(strings.Split(sarr, ","))
	if len(arr) == 1 {
		s := arr[0]
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			s = s[1 : len(s)-1]
			arr = common.RemoveEmptyStrings(strings.Split(s, " "))
		}
	}
	return arr
}

func (s *Slack) findUserGroupIDByName(groups []slack.UserGroup, name string) string {

	for _, group := range groups {
		if (!utils.IsEmpty(group.Handle) && (group.Handle == name)) ||
			(!utils.IsEmpty(group.Name) && (group.Name == name)) {
			return group.ID
		}
	}
	return name
}

func (s *Slack) findUserGroupNameByID(groups []slack.UserGroup, ID string) string {

	for _, group := range groups {
		if group.ID == ID {
			v := group.Handle
			if utils.IsEmpty(v) {
				v = group.Name
			}
			return v
		}
	}
	return ID
}

func (s *Slack) formBlocks(cmd common.Command, command, group string, fields []common.Field, params common.ExecuteParams,
	u *slack.User, groups []slack.UserGroup) ([]slack.Block, error) {

	blocks := []slack.Block{}

	interactionID := s.buildInteractionID(command, group)

	// to do
	confirmationParams := make(common.ExecuteParams)
	for k, v := range params {
		confirmationParams[k] = v
	}

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
		fn := field.Name
		if !utils.IsEmpty(params[fn]) {
			switch field.Type {
			case common.FieldTypeMultiSelect, common.FieldTypeDynamicMultiSelect:
				switch v := params[fn].(type) {
				case []string:
					def = strings.Join(v, ",")
				case string:
					def = v
				}
			default:
				def = fmt.Sprintf("%v", params[fn])
			}
		}
		if utils.IsEmpty(def) {
			def = field.Default
		}

		if utils.IsEmpty(confirmationParams[field.Name]) {
			confirmationParams[field.Name] = def
		}

		// updating values from params if exists
		currentValues := field.Values
		if paramValues, exists := params[field.Name+"_values"]; exists {
			switch v := paramValues.(type) {
			case []string:
				currentValues = v
			case string:
				currentValues = strings.Split(v, ",")
			}
		}
		if utils.IsEmpty(currentValues) {
			currentValues = []string{" "}
		}

		l := slack.NewTextBlockObject(slack.PlainTextType, field.Label, false, false)
		var h *slack.TextBlockObject
		if !utils.IsEmpty(field.Hint) {
			h = slack.NewTextBlockObject(slack.PlainTextType, field.Hint, false, false)
		}

		addToBlocks := true
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
				for _, v := range currentValues {
					block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h)
					if v == def {
						dBlock = block
					}
					options = append(options, block)
				}
				optType = slack.OptTypeStatic
				if len(options) == 0 && !utils.IsEmpty(def) {
					options = append(options, slack.NewOptionBlockObject(def, slack.NewTextBlockObject(slack.PlainTextType, def, false, false), h))
				}
			} else if !utils.IsEmpty(def) {
				dBlock = slack.NewOptionBlockObject(def, slack.NewTextBlockObject(slack.PlainTextType, def, false, false), h)
			}
			e := slack.NewOptionsSelectBlockElement(optType, h, actionID, options...)
			if dBlock != nil {
				e.InitialOption = dBlock
			}
			if field.Type == common.FieldTypeDynamicSelect {
				min := s.options.MinQueryLength
				e.MinQueryLength = &min
			}
			el = e
		case common.FieldTypeMultiSelect, common.FieldTypeDynamicMultiSelect:
			options := []*slack.OptionBlockObject{}
			dBlocks := []*slack.OptionBlockObject{}
			optType := slack.MultiOptTypeExternal
			if field.Type == common.FieldTypeMultiSelect {
				arr := s.parseArrayValues(def)
				for _, v := range currentValues {
					block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h)
					if utils.Contains(arr, v) {
						dBlocks = append(dBlocks, block)
					}
					options = append(options, block)
				}
				optType = slack.MultiOptTypeStatic
				if len(options) == 0 && !utils.IsEmpty(def) {
					options = append(options, slack.NewOptionBlockObject(def, slack.NewTextBlockObject(slack.PlainTextType, def, false, false), h))
				}
			} else if !utils.IsEmpty(def) {
				arr := s.parseArrayValues(def)
				for _, v := range arr {
					block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h)
					dBlocks = append(dBlocks, block)
				}
			}
			e := slack.NewOptionsMultiSelectBlockElement(optType, h, actionID, options...)
			if len(dBlocks) > 0 {
				e.InitialOptions = dBlocks
			}
			if field.Type == common.FieldTypeDynamicMultiSelect {
				min := s.options.MinQueryLength
				e.MinQueryLength = &min
			}
			el = e
		case common.FieldTypeRadionButtons:
			options := []*slack.OptionBlockObject{}
			var dBlock *slack.OptionBlockObject
			for _, v := range field.Values {
				block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h)
				if v == def {
					dBlock = block
				}
				options = append(options, block)
			}
			if len(options) == 0 && !utils.IsEmpty(def) {
				options = append(options, slack.NewOptionBlockObject(def, slack.NewTextBlockObject(slack.PlainTextType, def, false, false), h))
			}
			e := slack.NewRadioButtonsBlockElement(actionID, options...)
			if dBlock != nil {
				e.InitialOption = dBlock
			}
			el = e
		case common.FieldTypeCheckboxes:
			options := []*slack.OptionBlockObject{}
			dBlocks := []*slack.OptionBlockObject{}
			arr := s.parseArrayValues(def)
			for _, v := range field.Values {
				block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h)
				if utils.Contains(arr, v) {
					dBlocks = append(dBlocks, block)
				}
				options = append(options, block)
			}
			if len(options) == 0 && !utils.IsEmpty(def) {
				options = append(options, slack.NewOptionBlockObject(def, slack.NewTextBlockObject(slack.PlainTextType, def, false, false), h))
			}
			e := slack.NewCheckboxGroupsBlockElement(actionID, options...)
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
		case common.FieldTypeMarkdown:
			e := slack.NewTextBlockObject(slack.MarkdownType, def, false, false)
			blocks = append(blocks, slack.NewSectionBlock(e, nil, nil))
			addToBlocks = false
		case common.FieldTypeUser:
			e := slack.NewOptionsSelectBlockElement(slack.OptTypeUser, h, actionID)
			if !utils.IsEmpty(def) {
				e.InitialUser = def
			}
			el = e
		case common.FieldTypeMultiUser:
			e := slack.NewOptionsMultiSelectBlockElement(slack.MultiOptTypeUser, h, actionID)
			if !utils.IsEmpty(def) {
				e.InitialUsers = s.parseArrayValues(def)
			}
			el = e
		case common.FieldTypeChannel:
			e := slack.NewOptionsSelectBlockElement(slack.OptTypeChannels, h, actionID)
			e.InitialChannel = def
			el = e
		case common.FieldTypeMultiChannel:
			e := slack.NewOptionsMultiSelectBlockElement(slack.MultiOptTypeChannels, h, actionID)
			if !utils.IsEmpty(def) {
				e.InitialChannels = strings.Split(def, ",")
			}
			el = e
		case common.FieldTypeGroup:
			options := []*slack.OptionBlockObject{}
			var dBlock *slack.OptionBlockObject
			if !utils.IsEmpty(def) {
				groupName := s.findUserGroupNameByID(groups, def)
				dBlock = slack.NewOptionBlockObject(groupName, slack.NewTextBlockObject(slack.PlainTextType, groupName, false, false), h)
			}
			e := slack.NewOptionsSelectBlockElement(slack.OptTypeExternal, h, actionID, options...)
			if dBlock != nil {
				e.InitialOption = dBlock
			}
			min := s.options.MinQueryLength
			e.MinQueryLength = &min
			el = e
		case common.FieldTypeMultiGroup:
			options := []*slack.OptionBlockObject{}
			dBlocks := []*slack.OptionBlockObject{}
			arr := s.parseArrayValues(def)
			for _, v := range arr {
				groupName := s.findUserGroupNameByID(groups, v)
				block := slack.NewOptionBlockObject(groupName, slack.NewTextBlockObject(slack.PlainTextType, groupName, false, false), h)
				dBlocks = append(dBlocks, block)
			}
			e := slack.NewOptionsMultiSelectBlockElement(slack.MultiOptTypeExternal, h, actionID, options...)
			if len(dBlocks) > 0 {
				e.InitialOptions = dBlocks
			}
			min := s.options.MinQueryLength
			e.MinQueryLength = &min
			el = e
		default:
			e := slack.NewPlainTextInputBlockElement(h, actionID)
			e.InitialValue = def
			e.DispatchActionConfig = dac
			el = e
		}

		if addToBlocks {
			b = slack.NewInputBlock("", l, nil, el)
			if b != nil {
				b.DispatchAction = dac != nil
				b.Optional = !field.Required
				blocks = append(blocks, b)
			}
		}
	}

	if len(blocks) == 0 {
		return blocks, nil
	}

	divider := slack.NewDividerBlock()
	blocks = append(blocks, divider)

	submit := slack.NewButtonBlockElement(slackSubmitAction, "", slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonSubmitCaption, false, false))
	submit.Style = slack.Style(s.options.ButtonSubmitStyle)

	// to think about it, not sure if it's needed
	confirmation := cmd.Confirmation(confirmationParams)
	if !utils.IsEmpty(confirmation) {

		tmp := confirmation
		submit.Confirm = slack.NewConfirmationBlockObject(
			slack.NewTextBlockObject(slack.PlainTextType, s.options.TitleConfirmation, false, false),
			slack.NewTextBlockObject(slack.PlainTextType, tmp, false, false),
			slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonConfirmCaption, false, false),
			slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonRejectCaption, false, false),
		)
	}

	cancel := slack.NewButtonBlockElement(slackCancelAction, "", slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonCancelCaption, false, false))
	cancel.Style = slack.Style(s.options.ButtonCancelStyle)

	ab := slack.NewActionBlock(interactionID, submit, cancel)
	blocks = append(blocks, ab)

	return blocks, nil
}

func (s *Slack) replyForm(cmd common.Command, command, group string, fields []common.Field, params common.ExecuteParams,
	m *slackMessageInfo, u *slack.User, groups []slack.UserGroup, replier *slacker.ResponseReplier) (bool, error) {

	mThreadTS := m.threadTS
	opts := []slacker.PostOption{}
	replyInThread := !utils.IsEmpty(mThreadTS)
	if replyInThread {
		opts = append(opts, slacker.SetThreadTS(mThreadTS))
	}

	if utils.IsEmpty(m.botID) {
		opts = append(opts, slacker.SetEphemeral(m.userID))
	}

	// pass message timestamp & text to each button
	button := &SlackButton{
		Type:      slackButtonFormType,
		ChannelID: m.channelID,
		UserID:    m.userID,
		Command:   command,
		Group:     group,
		Params:    params,
		Timestamp: m.timestamp,
		ThreadTS:  mThreadTS,
		Text:      m.text,
		Wrapped:   m.wrapped,
		Wrapper:   m.wrapper,
	}

	blocks, err := s.formBlocks(cmd, command, group, fields, params, u, groups)
	if err != nil {
		return false, err
	}

	s.addReaction(m, s.options.ReactionDialog)

	ts, err := replier.PostBlocks(m.channelID, blocks, opts...)
	if err != nil {
		s.removeReaction(m, s.options.ReactionDialog)
		return false, err
	}

	nParams := make(common.ExecuteParams)
	for _, v := range fields {
		nParams[v.Name] = v.Default
	}

	s.fields.Set(ts, nParams, ttlcache.PreviousOrDefaultTTL)
	s.buttons.Set(ts, button, ttlcache.PreviousOrDefaultTTL)
	return true, nil
}

func (s *Slack) askApproval(approval common.Approval, message, channel string, command, group string,
	params common.ExecuteParams, m *slackMessageInfo, replier *slacker.ResponseReplier) (bool, error) {

	opts := []slacker.PostOption{}

	blocks := []slack.Block{}
	interactionID := s.buildInteractionID(command, group)

	blocks = append(blocks, slack.NewSectionBlock(
		slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
		[]*slack.TextBlockObject{}, nil,
	))

	reasons := approval.Reasons()
	if len(reasons) > 0 || approval.Description() {
		divider := slack.NewDividerBlock()
		blocks = append(blocks, divider)
	}

	if len(reasons) > 0 {

		actionID := s.buildActionID(interactionID, slackApprovalReasons)
		options := []*slack.OptionBlockObject{}
		for _, v := range reasons {
			block := slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), nil)
			options = append(options, block)
		}
		e := slack.NewCheckboxGroupsBlockElement(actionID, options...)
		l := slack.NewTextBlockObject(slack.PlainTextType, slackApprovalReasonsCaption, false, false)
		b := slack.NewInputBlock("", l, nil, e)
		if b != nil {
			blocks = append(blocks, b)
		}
	}

	if approval.Description() {

		actionID := s.buildActionID(interactionID, slackApprovalDescription)
		e := slack.NewPlainTextInputBlockElement(nil, actionID)
		e.Multiline = true
		l := slack.NewTextBlockObject(slack.PlainTextType, slackApprovalDescriptionCaption, false, false)
		b := slack.NewInputBlock("", l, nil, e)
		if b != nil {
			blocks = append(blocks, b)
		}
	}

	// pass message timestamp & text to each button
	button := &SlackButton{
		Type:      slackButtonApprovalType,
		ChannelID: m.channelID,
		UserID:    m.userID,
		Command:   command,
		Group:     group,
		Params:    params,
		Timestamp: m.timestamp,
		ThreadTS:  m.threadTS,
		Text:      m.text,
		Wrapped:   m.wrapped,
		Wrapper:   m.wrapper,
	}

	submit := slack.NewButtonBlockElement(slackSubmitAction, "", slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonApproveCaption, false, false))
	submit.Style = slack.Style(s.options.ButtonSubmitStyle)

	cancel := slack.NewButtonBlockElement(slackCancelAction, "", slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonRejectCaption, false, false))
	cancel.Style = slack.Style(s.options.ButtonCancelStyle)

	ab := slack.NewActionBlock(interactionID, submit, cancel)
	blocks = append(blocks, ab)

	s.addReaction(m, s.options.ReactionDialog)
	ts, err := replier.PostBlocks(channel, blocks, opts...)
	if err != nil {
		s.removeReaction(m, s.options.ReactionDialog)
		return false, err
	}
	s.buttons.Set(ts, button, ttlcache.PreviousOrDefaultTTL)
	return true, nil
}

func (s *Slack) postUserCommand(cmd common.Command, m *slackMessageInfo, u *slack.User,
	replier interface{}, params common.ExecuteParams, response common.Response, reaction bool) error {

	//  should check parent if its visible and its thread message

	cName := cmd.Name()
	commands := m.commands

	user := &SlackUser{
		id:       m.userID,
		commands: commands,
	}
	if u != nil {
		user.name = u.Name
		user.timezone = u.TZ
	}

	mChannel, mTimeStamp, mThreadTS := s.getChannelAndTimestamp(cmd.Channel(), m)

	channel := &SlackChannel{
		id: mChannel,
	}

	msg1 := &SlackMessage{
		id:       mTimeStamp,
		user:     user,
		threadTS: mThreadTS,
		channel:  channel,
	}

	if reaction {
		s.addReaction(m, s.options.ReactionDoing)
	}

	start := time.Now()
	executor, message, attachments, err := cmd.Execute(s, msg1, params)
	if err != nil {
		if reaction {
			s.replyError(cName, m, replier, err, "", attachments)
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

		ts, err = s.reply(cName, m, replier, message, mChannel, attachments, r, &start, r.error)
		if err != nil {
			if reaction {
				s.replyError(cName, m, replier, err, "", attachments)
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

	ts2 := m.threadTS
	if r.visible {
		ts2 = ts
	}
	msg2 := &SlackMessage{
		id:       ts,
		visible:  r.visible,
		user:     user,
		threadTS: ts2,
		channel:  channel,
	}

	return executor.After(msg2)
}

func (s *Slack) postJobCommand(cmd common.Command, m *slackMessageInfo,
	replier interface{}) error {

	cName := cmd.Name()

	mChannel, mTimeStamp, mThreadTS := s.getChannelAndTimestamp(cmd.Channel(), m)

	channel := &SlackChannel{
		id: mChannel,
	}

	msg1 := &SlackMessage{
		id:       mTimeStamp,
		threadTS: mThreadTS,
		channel:  channel,
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

	ts, err := s.reply(cName, m, replier, message, mChannel, attachments, r, &start, r.error)
	if err != nil {
		return err
	}

	msg2 := &SlackMessage{
		id:       ts,
		visible:  r.visible,
		threadTS: m.threadTS,
		channel:  channel,
	}

	return executor.After(msg2)
}

func (s *Slack) formNeeded(fields []common.Field, params map[string]interface{}) bool {

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

func (s *Slack) approvalNeeded(approval common.Approval, m *slackMessageInfo, u *slack.User, params common.ExecuteParams) (string, string) {

	if approval == nil {
		return "", ""
	}

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
		id:       m.timestamp,
		user:     user,
		threadTS: m.threadTS,
		channel:  channel,
	}

	chl := approval.Channel(s, msg, params)
	chl = strings.TrimSpace(chl)
	if utils.IsEmpty(chl) {
		return "", ""
	}

	message := approval.Message(s, msg, params)
	message = strings.TrimSpace(message)
	if utils.IsEmpty(message) {
		return "", chl
	}

	return message, chl
}

func (s *Slack) getFieldsByType(cmd common.Command, types []string) []string {

	r := []string{}

	fields := cmd.Fields(s, nil, nil, nil)
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
		m.threadTS = parent.ParentID()
	}

	params, cmd, group, _, _, _ := s.findParams(false, m)
	if cmd == nil {
		s.logger.Debug("Slack command not found for text: %s", text)
		return nil
	}

	groups, err := s.client.SlackClient().GetUserGroups(slack.GetUserGroupsOptionIncludeCount(true), slack.GetUserGroupsOptionIncludeUsers(true))
	if err != nil {
		s.logger.Error("Slack getting user group error: %s", err)
		return nil
	}

	commands, err := s.listUserCommands(m.userID, groups)
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

	fields := cmd.Fields(s, parent, params, nil)
	if s.formNeeded(fields, params) {
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
			typ:       event.Type,
			text:      event.Text,
			userID:    userID,
			botID:     event.BotID,
			channelID: event.ChannelID,
			timestamp: event.TimeStamp,
			threadTS:  event.ThreadTimeStamp,
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

		groups := []slack.UserGroup{}
		if eCmd.Permissions() {

			grps, err := s.client.SlackClient().GetUserGroups(slack.GetUserGroupsOptionIncludeCount(true), slack.GetUserGroupsOptionIncludeUsers(true))
			if err != nil {
				s.logger.Error("Slack getting user group error: %s", err)
				return
			}
			groups = grps

			commands, err := s.listUserCommands(userID, groups)
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
			id:       m.timestamp,
			user:     mUser,
			threadTS: m.threadTS,
			channel:  mChannel,
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

		list := []string{common.FieldTypeSelect, common.FieldTypeMultiSelect, common.FieldTypeEdit}
		only := s.getFieldsByType(cmd, list)

		rFields := cmd.Fields(s, msg, eParams, only)
		rParams := eParams

		approvalCmd := cmd
		approvalCommand := rCommand
		approvalGroup := rGroup
		approvalParams := rParams

		if wrapper {

			rCommand = ""
			if wrappedCmd != nil {
				rCommand = wrappedCmd.Name()
			} else {
				s.unsupportedCommandHandler(cc)
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

				// check for wrapped command
				if len(groups) == 0 {
					grps, err := s.client.SlackClient().GetUserGroups(slack.GetUserGroupsOptionIncludeCount(true), slack.GetUserGroupsOptionIncludeUsers(true))
					if err != nil {
						s.logger.Error("Slack getting user group error: %s", err)
						return
					}
					groups = grps
				}

				commands, err := s.listUserCommands(userID, groups)
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

			list := []string{common.FieldTypeSelect, common.FieldTypeMultiSelect, common.FieldTypeEdit}
			only := s.getFieldsByType(wrappedCmd, list)

			rFields = wrappedCmd.Fields(s, msg, rParams, only)

			rParams = wrappedParams
			m.wrapped = fmt.Sprintf("%s/%s", rGroup, rCommand)
			m.wrapper = fmt.Sprintf("%s/%s", eGroup, eCommand)

			approvalCmd = wrappedCmd
			approvalCommand = rCommand
			approvalGroup = rGroup
			approvalParams = rParams
		}

		if s.formNeeded(rFields, rParams) && user != nil {
			shown, err := s.replyForm(cmd, rCommand, rGroup, rFields, rParams, m, user, groups, replier)
			if err != nil {
				s.replyError(cName, m, replier, err, "", []*common.Attachment{})
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
		message, channel := s.approvalNeeded(approval, m, user, approvalParams)
		if !utils.IsEmpty(message) {
			shown, err := s.askApproval(approval, message, channel, approvalCommand, approvalGroup, approvalParams, m, replier)
			if err != nil {
				s.replyError(cName, m, replier, err, "", []*common.Attachment{})
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
		s.fields.Set(m.timestamp, rParams, ttlcache.PreviousOrDefaultTTL)
	}
	return def
}

func (s *Slack) removeMessage(m *slackMessageInfo, responseURL string) {
	s.client.SlackClient().PostEphemeral(m.channelID, m.userID,
		slack.MsgOptionReplaceOriginal(responseURL),
		slack.MsgOptionDeleteOriginal(responseURL),
	)
}

func (s *Slack) replaceMessage(m *slackMessageInfo, responseURL string, blocks []slack.Block) (string, error) {

	return s.client.SlackClient().PostEphemeral(m.channelID, m.userID,
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionReplaceOriginal(responseURL),
	)
}

func (s *Slack) replaceApprovalMessage(m *slackMessageInfo, responseURL string, mblocks []slack.Block, message string) (string, error) {

	blocks := []slack.Block{}
	for _, block := range mblocks {

		arr := []slack.MessageBlockType{slack.MBTInput, slack.MBTAction}

		if !utils.Contains(arr, block.BlockType()) {
			blocks = append(blocks, block)
		}
	}

	if !utils.IsEmpty(message) {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
			[]*slack.TextBlockObject{}, nil,
		))
	}
	return s.replaceMessage(m, responseURL, blocks)
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

func (s *Slack) PostMessage(channel string, text string, attachments []*common.Attachment, user common.User, parent common.Message, response common.Response) (string, error) {

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
		return "", err
	}

	blocks := []slack.Block{}
	blocks = append(blocks, slack.NewSectionBlock(
		slack.NewTextBlockObject(slack.MarkdownType, text, false, false),
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
	_, timeStamp, err := client.PostMessage(channelID, options...)
	return timeStamp, err
}

func (s *Slack) getActionValue(field *common.Field, state slack.BlockAction) interface{} {

	groups := []slack.UserGroup{}
	if field != nil && utils.Contains([]common.FieldType{common.FieldTypeGroup, common.FieldTypeMultiGroup}, field.Type) {
		grs, err := s.client.SlackClient().GetUserGroups()
		if err == nil {
			groups = grs
		}
	}

	var v interface{}
	v = state.Value
	st := string(state.Type)
	switch st {
	case "number_input":
		v = state.Value
	case "datepicker":
		v = state.SelectedDate
	case "timepicker":
		v = state.SelectedTime
	case "static_select", "external_select", "radio_buttons":
		v2 := state.SelectedOption.Value
		if field != nil && !utils.IsEmpty(v2) {
			switch field.Type {
			case common.FieldTypeGroup:
				v2 = s.findUserGroupIDByName(groups, v2)
			}
		}
		v = v2
	case "multi_static_select", "multi_external_select":
		arr := []string{}
		for _, v2 := range state.SelectedOptions {
			v3 := v2.Value
			if field != nil && !utils.IsEmpty(v3) {
				switch field.Type {
				case common.FieldTypeMultiGroup:
					v3 = s.findUserGroupIDByName(groups, v3)
				}
			}
			arr = append(arr, v3)
		}
		v = arr
	case "checkboxes":
		arr := []string{}
		for _, v2 := range state.SelectedOptions {
			arr = append(arr, v2.Value)
		}
		v = strings.Join(arr, ",")
		if utils.IsEmpty(v) {
			v = fmt.Sprintf("%v", false)
		}
	case "users_select":
		v = state.SelectedUser
	case "multi_users_select":
		arr := []string{}
		arr = append(arr, state.SelectedUsers...)
		v = arr
	case "channels_select":
		v = state.SelectedChannel
	case "multi_channels_select":
		arr := []string{}
		arr = append(arr, state.SelectedChannels...)
		v = arr
	}
	return v
}

func (s *Slack) findField(fields []common.Field, name string) *common.Field {

	for _, f := range fields {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func (s *Slack) approvalReply(approval common.Approval, approved bool, approvedRejected string,
	states *slack.BlockActionStates, m *slackMessageInfo, replier *slacker.ResponseReplier) {

	if states == nil {
		return
	}

	reasons := ""
	description := ""

	for _, v1 := range states.Values {
		for k2, v2 := range v1 {

			_, actionID := s.getActionID(k2)
			if utils.IsEmpty(actionID) {
				continue
			}
			switch actionID {
			case slackApprovalReasons:
				for _, v3 := range v2.SelectedOptions {
					v := v3.Value
					if utils.IsEmpty(v) {
						continue
					}
					if utils.IsEmpty(reasons) {
						reasons = v
					} else {
						reasons = fmt.Sprintf("%s, %s", reasons, v)
					}
				}
			case slackApprovalDescription:
				description = v2.Value
			}
		}
	}

	if !utils.IsEmpty(reasons) {
		reasons = strings.TrimSpace(fmt.Sprintf("%s %s", s.options.ApprovalReasons, reasons))
	}

	if !utils.IsEmpty(description) {
		description = strings.TrimSpace(fmt.Sprintf("%s %s", s.options.ApprovalDescription, description))
	}

	message := ""
	if !utils.IsEmpty(reasons) {
		message = reasons
	}

	if !utils.IsEmpty(description) {
		message = fmt.Sprintf("%s\n%s", message, description)
	}

	if !utils.IsEmpty(approvedRejected) {
		message = fmt.Sprintf("%s\n\n%s", message, approvedRejected)
	}

	if utils.IsEmpty(message) {
		return
	}

	r := &SlackResponse{
		visible: approval.Visible(),
	}
	s.reply(m.text, m, replier, message, "", nil, r, nil, false)
}

func (s *Slack) formButtonCallbackHandler(m *slackMessageInfo, action *slack.BlockAction, button *SlackButton, ctx *slacker.InteractionContext) {

	callback := ctx.Callback()
	replier := ctx.Response()

	cmd := s.processors.FindCommand(button.Group, button.Command)
	if cmd == nil {
		s.logger.Error("Slack command is missed.")
		s.removeReaction(m, s.options.ReactionDialog)
		return
	}

	params := button.Params

	if action.ActionID == slackSubmitAction && button.Type == slackButtonFormType {

		states := callback.BlockActionState
		if states != nil && len(states.Values) > 0 {

			for _, v1 := range states.Values {
				for k2, v2 := range v1 {
					cmd, _, name := s.getCommandGroupField(k2)
					if utils.IsEmpty(name) {
						continue
					}
					field := s.findField(cmd.Fields(s, nil, nil, nil), name)
					params[name] = s.getActionValue(field, v2)
				}
			}
		}

		// check cache fields
		cParams := params
		fields := s.fields.Get(callback.Container.MessageTs)
		if fields != nil {
			for k, v := range fields.Value() {
				if _, ok := cParams[k]; ok {
					continue
				}
				cParams[k] = v
			}
		}
		params = cParams
	}

	approvedRejected := ""

	switch button.Type {
	case slackButtonFormType:

		m.userID = button.UserID
		m.channelID = button.ChannelID
		m.timestamp = button.Timestamp
		m.text = button.Text
		m.wrapped = button.Wrapped
		m.wrapper = button.Wrapper

		approval := cmd.Approval()
		if action.ActionID == slackSubmitAction {

			message, channel := s.approvalNeeded(approval, m, &callback.User, params)
			if !utils.IsEmpty(message) {
				shown, err := s.askApproval(approval, message, channel, button.Command, button.Group, params, m, replier)
				if err != nil {
					s.replyError(button.Command, m, replier, err, "", []*common.Attachment{})
					s.addRemoveReactions(m, s.options.ReactionFailed, s.options.ReactionDoing)
					return
				}
				if shown {
					s.removeMessage(m, callback.ResponseURL)
					return
				}
			}
		}
		s.removeMessage(m, callback.ResponseURL)

	case slackButtonApprovalType:

		if !s.options.ApprovalAllowed {
			if callback.User.ID == button.UserID {
				s.logger.Error("Slack same user cannot approve its action.")
				return
			}
		}

		// this is approval message TS
		m.timestamp = callback.Container.MessageTs

		reaction := common.IfDef(action.ActionID == slackSubmitAction, s.options.ReactionApproved, s.options.ReactionRejected)
		mdef := common.IfDef(action.ActionID == slackSubmitAction, s.options.ApprovedMessage, s.options.RejectedMessage)
		if !utils.IsEmpty(mdef) {
			user := fmt.Sprintf("<@%s>", callback.User.ID)
			approvedRejected = fmt.Sprintf(mdef.(string), user, time.Now().Format("15:04:05"))
			approvedRejected = fmt.Sprintf(":%s: %s", reaction, approvedRejected)
		}
		s.replaceApprovalMessage(m, callback.ResponseURL, callback.Message.Blocks.BlockSet, approvedRejected)

		// set original message TS & text
		m.userID = button.UserID
		m.channelID = button.ChannelID
		m.timestamp = button.Timestamp
		m.text = button.Text
		m.threadTS = button.ThreadTS
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

		if !utils.IsEmpty(button.Wrapper) {
			arr := strings.Split(button.Wrapper, "/")
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
		if !utils.IsEmpty(button.Wrapped) {
			arr := strings.Split(button.Wrapped, "/")
			if len(arr) == 2 {
				eParams, _, _, _, _, _ := s.findParams(!utils.IsEmpty(button.Wrapper), m)
				rParams = common.MergeInterfaceMaps(rParams, eParams)
			}
		}

		if button.Type == slackButtonApprovalType {
			s.approvalReply(cmd.Approval(), true, approvedRejected, callback.BlockActionState, m, replier)
		}

		err := s.postUserCommand(cmd, m, &callback.User, replier, rParams, response, true)
		if err != nil {
			s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
			return
		}
		s.fields.Set(callback.Container.MessageTs, rParams, ttlcache.PreviousOrDefaultTTL)

	default:

		if button.Type == slackButtonApprovalType {
			s.approvalReply(cmd.Approval(), false, approvedRejected, callback.BlockActionState, m, replier)
		}
		s.addReaction(m, s.options.ReactionFailed)
	}
	s.buttons.Delete(callback.Container.MessageTs)
}

func (s *Slack) formCallbackHandler(ctx *slacker.InteractionContext) {

	callback := ctx.Callback()

	m := &slackMessageInfo{
		typ:       callback.Container.Type,
		text:      "", // get this from button value
		userID:    callback.User.ID,
		botID:     "",
		channelID: callback.Container.ChannelID,
		timestamp: callback.Container.MessageTs,
		threadTS:  callback.Container.ThreadTs,
	}

	actions := callback.ActionCallback.BlockActions
	if len(actions) == 0 {
		s.logger.Error("Slack actions are not defined.")
		s.removeReaction(m, s.options.ReactionDialog)
		return
	}

	item := s.buttons.Get(m.timestamp)
	if item == nil {
		s.logger.Error("Slack no button cache defined.")
		s.removeReaction(m, s.options.ReactionDialog)
		return
	}

	value := item.Value()
	if value == nil {
		s.logger.Error("Slack no value defined.")
		s.removeReaction(m, s.options.ReactionDialog)
		return
	}

	action := actions[0]
	if utils.Contains([]string{slackSubmitAction, slackCancelAction}, action.ActionID) {
		s.formButtonCallbackHandler(m, action, value, ctx)
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
		id:       m.timestamp,
		visible:  !callback.Container.IsEphemeral,
		user:     user,
		threadTS: m.threadTS,
		channel:  channel,
	}

	// find all fields that depend on name
	deps := []string{}
	skip := []common.FieldType{common.FieldTypeDynamicSelect, common.FieldTypeDynamicMultiSelect}
	groupsNeeded := false

	allFields := cmd.Fields(s, msg, nil, nil)
	for _, field := range allFields {
		if utils.Contains(field.Dependencies, name) && !utils.Contains(skip, field.Type) {
			deps = append(deps, field.Name)
		}
		if utils.Contains([]common.FieldType{common.FieldTypeGroup, common.FieldTypeMultiGroup}, field.Type) {
			groupsNeeded = true
		}
	}

	params := make(common.ExecuteParams)
	params[name] = action.Value

	for _, v1 := range callback.BlockActionState.Values {
		for k2, v2 := range v1 {
			c2, _, n2 := s.getCommandGroupField(k2)
			if utils.IsEmpty(n2) {
				continue
			}
			field := s.findField(c2.Fields(s, nil, nil, nil), n2)
			params[n2] = s.getActionValue(field, v2)
		}
	}

	// get dependent fields
	depFields := cmd.Fields(s, msg, params, deps)
	for _, field := range depFields {
		if !utils.Contains(deps, field.Name) {
			continue
		}
		// check if fields have values to update
		if len(field.Values) > 0 {
			params[field.Name+"_values"] = field.Values
		}
		if !utils.IsEmpty(field.Default) {
			params[field.Name] = field.Default
		}
	}

	// keep old values if they exist (which not in params)
	cParams := params
	cache := s.fields.Get(callback.Container.MessageTs)
	if cache != nil {
		for k, v := range cache.Value() {
			if _, ok := cParams[k]; ok {
				continue
			}
			cParams[k] = v
		}
	}

	s.fields.Set(callback.Container.MessageTs, cParams, ttlcache.PreviousOrDefaultTTL)

	if len(deps) == 0 {
		return
	}

	u := s.getSlackUser(m.userID, m.botID)
	if u == nil {
		return
	}

	m.userID = value.UserID
	m.channelID = value.ChannelID
	m.timestamp = value.Timestamp
	m.threadTS = value.ThreadTS
	m.text = value.Text
	m.wrapped = value.Wrapped
	m.wrapper = value.Wrapper

	groups := []slack.UserGroup{}
	if groupsNeeded {
		grs, err := s.client.SlackClient().GetUserGroups()
		if err == nil {
			groups = grs
		}
	}

	blocks, err := s.formBlocks(cmd, command, group, allFields, params, u, groups)
	if err != nil {
		s.logger.Error("Slack couldn't generate form blocks, error: %s", err)
		return
	}

	options := []slack.MsgOption{}
	//options = append(options, slack.MsgOptionBlocks(blocks...), slack.MsgOptionReplaceOriginal(callback.ResponseURL), slack.MsgOptionPostEphemeral(m.userID)) // section doesn't work
	options = append(options, slack.MsgOptionBlocks(blocks...), slack.MsgOptionReplaceOriginal(callback.ResponseURL), slack.MsgOptionTS(m.threadTS)) // section works :(

	s.client.SlackClient().UpdateMessage(callback.Container.ChannelID, callback.Container.MessageTs, options...)
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

	interactionID, actionID := s.getActionID(ident)

	delim := "/"
	arr := strings.Split(interactionID, delim)
	if len(arr) < 1 {
		return nil, "", ""
	}

	c := ""
	g := ""
	f := actionID

	if len(arr) > 0 {
		c = strings.TrimSpace(arr[0])
	}
	if len(arr) > 1 {
		g = strings.TrimSpace(arr[1])
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
		id:       callback.Container.MessageTs,
		visible:  !callback.Container.IsEphemeral,
		user:     user,
		threadTS: callback.Container.ThreadTs,
		channel:  channel,
	}

	params := make(common.ExecuteParams)
	cache := s.fields.Get(callback.Container.MessageTs)
	if cache != nil {
		for k, v := range cache.Value() {
			if _, ok := params[k]; ok {
				continue
			}
			params[k] = v
		}
	}

	options := []*slack.OptionBlockObject{}
	value := callback.Value
	if utils.IsEmpty(value) {
		return
	}
	params[name] = value

	fields := cmd.Fields(s, msg, params, []string{name})
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

	values := field.Values

	switch field.Type {
	case common.FieldTypeGroup, common.FieldTypeMultiGroup:
		values = []string{}
		groups, _ := s.client.SlackClient().GetUserGroups()
		for _, g := range groups {
			values = append(values, g.Handle)
		}
	}

	if !utils.IsEmpty(field.Filter) {
		revls := []string{}
		re := regexp.MustCompile(field.Filter)
		if re != nil {
			for _, v := range values {
				if !re.MatchString(v) {
					continue
				}
				revls = append(revls, v)
			}
		}
		values = revls
	}

	re := regexp.MustCompile(value)
	if re == nil {
		return
	}

	for _, v := range values {

		if len(options) >= s.options.MaxQueryOptions {
			break
		}

		if re.MatchString(v) {

			var h *slack.TextBlockObject
			if !utils.IsEmpty(field.Hint) {
				h = slack.NewTextBlockObject(slack.PlainTextType, field.Hint, false, false)
			}

			options = append(options,
				slack.NewOptionBlockObject(v, slack.NewTextBlockObject(slack.PlainTextType, v, false, false), h))
		}
	}

	/*if len(options) == 0 {
		options = append(options,
			slack.NewOptionBlockObject(" ", slack.NewTextBlockObject(slack.PlainTextType, " ", false, false), nil))
	}*/

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
			if len(c.Fields(s, nil, nil, nil)) > 0 {
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
			if len(c.Fields(s, nil, nil, nil)) > 0 {
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
				if len(c.Fields(s, nil, nil, nil)) > 0 {
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

	ttl := 1 * 60 * 60 * time.Second
	if !utils.IsEmpty(options.CacheTTL) {
		ttl, _ = time.ParseDuration(options.CacheTTL)
	}

	buttonsOpts := []ttlcache.Option[string, *SlackButton]{}
	buttonsOpts = append(buttonsOpts, ttlcache.WithTTL[string, *SlackButton](ttl))
	buttons := ttlcache.New[string, *SlackButton](buttonsOpts...)
	go buttons.Start()

	fieldsOpts := []ttlcache.Option[string, common.ExecuteParams]{}
	fieldsOpts = append(fieldsOpts, ttlcache.WithTTL[string, common.ExecuteParams](ttl))
	fields := ttlcache.New[string, common.ExecuteParams](fieldsOpts...)
	go fields.Start()

	return &Slack{
		options:    options,
		processors: processors,
		logger:     observability.Logs(),
		meter:      observability.Metrics(),
		buttons:    buttons,
		fields:     fields,
	}
}
