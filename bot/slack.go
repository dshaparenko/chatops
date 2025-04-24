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
	"github.com/jinzhu/copier"
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

	ApprovalAny         bool
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
	ReactionForm     string
	ReactionApproval string
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

	UserGroupsInterval int
}

type SlackMessageKey struct {
	channelID string
	timestamp string
	threadTS  string
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
	slack       *Slack
	typ         string
	cmdText     string
	cmd         common.Command
	wrapper     common.Command
	originKey   *SlackMessageKey
	key         *SlackMessageKey
	user        *SlackUser
	caller      *SlackUser
	botID       string
	visible     bool
	responseURL string
	blocks      []slack.Block
	actions     []common.Action
	params      common.ExecuteParams
	fields      []common.Field
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

type SlackUserGroups struct {
	slack *Slack
	lock  sync.Mutex
	items []slack.UserGroup
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
	messages          *ttlcache.Cache[string, *SlackMessage]
	userGroups        SlackUserGroups
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

type SlackResponse struct {
	visible  bool
	original bool
	duration bool
	error    bool
	reaction bool
}

const (
	slackAPIURL                      = "https://slack.com/api/"
	slackFilesGetUploadURLExternal   = "files.getUploadURLExternal"
	slackFilesCompleteUploadExternal = "files.completeUploadExternal"
	slackFilesSharedPublicURL        = "files.sharedPublicURL"
	slackMaxTextBlockLength          = 3000
	slackTriggerOnCharacterEntered   = "on_character_entered"
	slackTriggerOnEnterPressed       = "on_enter_pressed"
	slackMessageType                 = "message"
	slackSlachCommand                = "slash_commands"
	slackAppMention                  = "app_mention"
)

const (
	slackSubmitAction = "submit"
	slackCancelAction = "cancel"

	slackFormFieldType      = "form-field"
	slackFormButtonType     = "form-button"
	slackApprovalFieldType  = "approval-field"
	slackApprovalButtonType = "approval-button"
	slackActionButtonType   = "action-button"

	slackApprovalReasons            = "approval-reasons"
	slackApprovalDescription        = "approval-description"
	slackApprovalReasonsCaption     = "Reasons"
	slackApprovalDescriptionCaption = "Description"
)

// SlackUserGroups

func (ugs *SlackUserGroups) refresh() {

	ugs.lock.Lock()
	defer ugs.lock.Unlock()
	groups, err := ugs.slack.client.SlackClient().GetUserGroups(slack.GetUserGroupsOptionIncludeCount(true), slack.GetUserGroupsOptionIncludeUsers(true))
	if err != nil {
		ugs.slack.logger.Error("Slack groups error: %s", err)
		return
	}
	copier.Copy(&ugs.items, &groups)
}

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

/*func (r *SlackResponse) Reaction() bool {
	return r.reaction
}*/

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
	return sm.key.timestamp
}

func (sm *SlackMessage) Visible() bool {

	return sm.visible
}

func (sm *SlackMessage) User() common.User {
	return sm.user
}

func (sm *SlackMessage) Caller() common.User {
	return sm.caller
}

func (sm *SlackMessage) userID() string {
	u := sm.user
	if u == nil {
		return ""
	}
	return u.id
}

func (sm *SlackMessage) Channel() common.Channel {
	return &SlackChannel{id: sm.key.channelID}
}

func (sm *SlackMessage) ParentID() string {
	return sm.key.threadTS
}

func (sm *SlackMessage) SetParentID(threadTS string) {
	sm.key.threadTS = threadTS
}

// SlackCacheMessageKey

func (smk *SlackMessageKey) String() string {
	return fmt.Sprintf("%s/%s", smk.channelID, smk.timestamp)
}

// Slack

func (s *Slack) Name() string {
	return "Slack"
}

func (s *Slack) getNewKey(channelID string, key *SlackMessageKey) *SlackMessageKey {

	r := &SlackMessageKey{}
	if key != nil {
		r.channelID = key.channelID
		r.timestamp = key.timestamp
		r.threadTS = key.threadTS
	}

	if !utils.IsEmpty(channelID) {
		if r.channelID != channelID {
			r.channelID = channelID
			r.timestamp = ""
			r.threadTS = ""
		}
	}
	return r
}

func (s *Slack) findMessageInCache(key *SlackMessageKey) *SlackMessage {

	if key == nil {
		return nil
	}
	item := s.messages.Get(key.String())
	if item != nil {
		return item.Value()
	}
	return nil
}

func (s *Slack) findParentMessageInCache(child *SlackMessage) *SlackMessage {
	if child.originKey == nil {
		return nil
	}
	return s.findMessageInCache(child.originKey)
}

func (s *Slack) findInitMessageInCache(child *SlackMessage) *SlackMessage {
	if child.originKey == nil {
		return child
	}
	m := s.findMessageInCache(child.originKey)
	if m != nil {
		if m.originKey == nil {
			return m
		} else {
			mi := s.findInitMessageInCache(m)
			if mi != nil {
				return mi
			}
		}
	}
	return nil
}

func (s *Slack) cloneMessage(m *SlackMessage) *SlackMessage {

	if m == nil {
		return nil
	}
	r := &SlackMessage{}
	err := copier.Copy(r, m)
	if err != nil {
		s.logger.Error("Slack message copy error: %s", err)
		return nil
	}
	return r
}

func (s *Slack) putMessageToCache(msg *SlackMessage) {

	if msg.key == nil {
		return
	}
	s.messages.Set(msg.key.String(), msg, ttlcache.DefaultTTL)
}

func (s *Slack) encodeActionID(id, typ, name string) string {
	return fmt.Sprintf("%s|%s|%s", id, typ, name)
}

func (s *Slack) decodeActionID(ident string) (string, string, string) {

	if utils.IsEmpty(ident) {
		return "", "", ""
	}
	arr := strings.SplitN(ident, "|", 3)
	if len(arr) < 3 {
		return "", "", ""
	}
	return arr[0], arr[1], arr[2]
}

func (s *Slack) prepareInputText(input, typ string) string {

	text := input
	switch typ {
	case slackSlachCommand:
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
	case slackAppMention:
		// <@Uq131312> command <param1>  => @bot command param1 param2
		items := strings.SplitN(text, ">", 2)
		if len(items) > 1 {
			text = strings.TrimSpace(items[1])
		}
	case slackMessageType:
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

func (s *Slack) buildActionBlocks(actions []common.Action, divider bool) []slack.Block {

	rb := []slack.Block{}

	if len(actions) == 0 {
		return rb
	}

	if divider {
		d := slack.NewDividerBlock()
		rb = append(rb, d)
	}

	elements := []slack.BlockElement{}
	blockID := common.UUID()

	for _, a := range actions {

		aName := a.Name()
		if utils.IsEmpty(aName) && utils.IsEmpty(a.Template) {
			continue
		}

		label := aName
		aLabel := a.Label()
		if !utils.IsEmpty(aLabel) {
			label = aLabel
		}
		actionID := s.encodeActionID(blockID, slackActionButtonType, aName)
		el := slack.NewButtonBlockElement(actionID, "", slack.NewTextBlockObject(slack.PlainTextType, label, false, false))

		style := a.Style()
		if !utils.IsEmpty(style) {
			el.Style = slack.Style(style)
		}
		elements = append(elements, el)
	}
	ab := slack.NewActionBlock(blockID, elements...)
	rb = append(rb, ab)

	return rb
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

func (s *Slack) AddAction(channelID, timestamp string, action common.Action) error {

	key := &SlackMessageKey{
		channelID: channelID,
		timestamp: timestamp,
		threadTS:  "",
	}

	m := s.findMessageInCache(key)
	if m == nil {
		err := fmt.Errorf("Slack message not found in %s with %s", channelID, timestamp)
		s.logger.Error(err)
		return err
	}

	aBlocks := s.buildActionBlocks([]common.Action{action}, true)
	if len(aBlocks) == 0 {
		return nil
	}

	blocks := []slack.Block{}
	for _, block := range m.blocks {

		arr := []slack.MessageBlockType{slack.MBTAction, slack.MBTDivider}
		flag := true
		if utils.Contains(arr, block.BlockType()) {

			_, ok := block.(*slack.DividerBlock)
			if !ok {
				flag = false
				continue
			}

			ab, ok := block.(*slack.ActionBlock)
			if !ok {
				continue
			}

			if ab.Elements == nil {
				continue
			}

			flag = len(ab.Elements.ElementSet) > 0
		}
		if flag {
			blocks = append(blocks, block)
		}
	}
	blocks = append(blocks, aBlocks...)

	m.actions = append(m.actions, action)
	m.blocks = blocks
	s.putMessageToCache(m)

	_, _, _, err := s.client.SlackClient().UpdateMessage(channelID, timestamp, slack.MsgOptionBlocks(blocks...))

	return err
}

func (s *Slack) AddActions(channelID, timestamp string, actions []common.Action) error {

	key := &SlackMessageKey{
		channelID: channelID,
		timestamp: timestamp,
		threadTS:  "",
	}

	m := s.findMessageInCache(key)
	if m == nil {
		err := fmt.Errorf("Slack message not found in %s with %s", channelID, timestamp)
		s.logger.Error(err)
		return err
	}

	aBlocks := s.buildActionBlocks(actions, true)
	if len(aBlocks) == 0 {
		return nil
	}

	blocks := []slack.Block{}
	for _, block := range m.blocks {

		arr := []slack.MessageBlockType{slack.MBTAction, slack.MBTDivider}
		flag := true
		if utils.Contains(arr, block.BlockType()) {

			_, ok := block.(*slack.DividerBlock)
			if !ok {
				flag = false
				continue
			}

			ab, ok := block.(*slack.ActionBlock)
			if !ok {
				continue
			}

			if ab.Elements == nil {
				continue
			}

			flag = len(ab.Elements.ElementSet) > 0
		}
		if flag {
			blocks = append(blocks, block)
		}
	}
	blocks = append(blocks, aBlocks...)

	m.actions = append(m.actions, actions...)
	m.blocks = blocks
	s.putMessageToCache(m)

	_, _, _, err := s.client.SlackClient().UpdateMessage(channelID, timestamp, slack.MsgOptionBlocks(blocks...))

	return err
}

func (s *Slack) RemoveAction(channelID, timestamp, name string) error {

	key := &SlackMessageKey{
		channelID: channelID,
		timestamp: timestamp,
		threadTS:  "",
	}

	m := s.findMessageInCache(key)
	if m == nil {
		err := fmt.Errorf("Slack message not found in %s with %s", channelID, timestamp)
		s.logger.Error(err)
		return err
	}

	// remove action from the list
	actions := []common.Action{}
	for _, a := range m.actions {
		if a.Name() == name {
			continue
		}
		actions = append(actions, a)
	}

	blocks := []slack.Block{}
	for _, block := range m.blocks {

		arr := []slack.MessageBlockType{slack.MBTAction}
		flag := true
		if utils.Contains(arr, block.BlockType()) {

			ab, ok := block.(*slack.ActionBlock)
			if !ok {
				continue
			}

			if ab.Elements == nil {
				continue
			}

			elements := []slack.BlockElement{}
			for _, el := range ab.Elements.ElementSet {

				bt, ok := el.(*slack.ButtonBlockElement)
				if !ok {
					continue
				}

				_, _, aName := s.decodeActionID(bt.ActionID)
				if aName != name {
					elements = append(elements, bt)
				}
			}

			flag = len(elements) > 0
			if flag {
				ab.Elements.ElementSet = elements
			}
		}
		if flag {
			blocks = append(blocks, block)
		}
	}
	m.actions = actions
	m.blocks = blocks
	s.putMessageToCache(m)

	_, _, _, err := s.client.SlackClient().UpdateMessage(channelID, timestamp, slack.MsgOptionBlocks(blocks...))

	return err
}

func (s *Slack) ClearActions(channelID, timestamp string) error {

	key := &SlackMessageKey{
		channelID: channelID,
		timestamp: timestamp,
		threadTS:  "",
	}

	m := s.findMessageInCache(key)
	if m == nil {
		err := fmt.Errorf("Slack message not found in %s with %s", channelID, timestamp)
		s.logger.Error(err)
		return err
	}

	blocks := []slack.Block{}
	for _, block := range m.blocks {

		arr := []slack.MessageBlockType{slack.MBTAction}
		flag := true
		if utils.Contains(arr, block.BlockType()) {

			ab, ok := block.(*slack.ActionBlock)
			if !ok {
				continue
			}

			if ab.Elements == nil {
				continue
			}

			flag = false
		}
		if flag {
			blocks = append(blocks, block)
		}
	}

	m.actions = nil
	m.blocks = blocks
	s.putMessageToCache(m)

	_, _, _, err := s.client.SlackClient().UpdateMessage(channelID, timestamp, slack.MsgOptionBlocks(blocks...))

	return err
}

func (s *Slack) addReaction(typ string, key *SlackMessageKey, name string) {

	if typ == slackSlachCommand {
		return
	}
	if key == nil {
		return
	}
	err := s.client.SlackClient().AddReaction(name, slack.NewRefToMessage(key.channelID, key.timestamp))
	if err != nil {
		s.logger.Error("Slack adding reaction error: %s", err)
	}
}

func (s *Slack) removeReaction(typ string, key *SlackMessageKey, name string) {

	if typ == slackSlachCommand {
		return
	}
	if key == nil {
		return
	}
	err := s.client.SlackClient().RemoveReaction(name, slack.NewRefToMessage(key.channelID, key.timestamp))
	if err != nil {
		s.logger.Error("Slack removing reaction error: %s", err)
	}
}

func (s *Slack) addRemoveReactions(typ string, key *SlackMessageKey, first, second string) {
	s.addReaction(typ, key, first)
	s.removeReaction(typ, key, second)
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

func (s *Slack) listUserCommands(userID string, groups []slack.UserGroup) []string {

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

	// add fake command to check by length
	if len(commands) == 0 {
		commands = append(commands, common.UUID())
	}

	return commands
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

func (s *Slack) findParams(wrapper bool, text string) (common.ExecuteParams, common.Command, string, common.ExecuteParams, common.Command, string) {

	ep := make(common.ExecuteParams)
	wp := make(common.ExecuteParams)

	// group command param1 param2
	// command param1 param2

	// find group, command, params

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

func (s *Slack) reply(m *SlackMessage, message, channel string,
	replier interface{}, attachments []*common.Attachment, actions []common.Action,
	response *SlackResponse, start *time.Time, error bool) (*SlackMessageKey, []slack.Block, error) {

	newKey := s.getNewKey(channel, m.key)
	userID := m.userID()

	text := s.prepareInputText(m.cmdText, m.typ)
	replyInThread := !utils.IsEmpty(newKey.threadTS)

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
			return nil, nil, err
		}
		opts = append(opts, slacker.SetAttachments(batts))
		atts = append(atts, batts...)
	}

	if replyInThread {
		opts = append(opts, slacker.SetThreadTS(newKey.threadTS))
	}

	if !visible {
		opts = append(opts, slacker.SetEphemeral(userID))
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
			text = m.cmdText
		}

		if !utils.IsEmpty(userID) {
			quote = append(quote, []*SlackRichTextQuoteElement{
				{Type: "user", UserID: userID},
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

		// build action blocks
		actBlocks := s.buildActionBlocks(actions, true)
		if len(actBlocks) > 0 {
			blocks = append(blocks, actBlocks...)
		}
	}

	// ResponseReplier => commands
	rr, ok := replier.(*slacker.ResponseReplier)
	if ok {
		ts, err := rr.PostBlocks(newKey.channelID, blocks, opts...)
		if err != nil {
			return nil, blocks, err
		}
		return &SlackMessageKey{
			channelID: newKey.channelID,
			timestamp: ts,
			threadTS:  newKey.threadTS,
		}, blocks, nil
	}

	// ResponseWriter => jobs
	rw, ok := replier.(*slacker.ResponseWriter)
	if ok {
		ts, err := rw.PostBlocks(newKey.channelID, blocks, opts...)
		if err != nil {
			return nil, blocks, err
		}
		return &SlackMessageKey{
			channelID: newKey.channelID,
			timestamp: ts,
			threadTS:  newKey.threadTS,
		}, blocks, nil
	}

	// default => command as text
	// dirty trick

	slackOpts := []slack.MsgOption{
		slack.MsgOptionText("", false),
		slack.MsgOptionAttachments(atts...),
		slack.MsgOptionBlocks(blocks...),
	}

	if replyInThread {
		slackOpts = append(slackOpts, slack.MsgOptionTS(newKey.threadTS))
	}

	if !visible {
		slackOpts = append(slackOpts, slack.MsgOptionPostEphemeral(userID))
	}

	_, ts, err := s.client.SlackClient().PostMessageContext(
		s.ctx,
		newKey.channelID,
		slackOpts...,
	)
	if err != nil {
		return nil, blocks, err
	}
	return &SlackMessageKey{
		channelID: newKey.channelID,
		timestamp: ts,
		threadTS:  newKey.threadTS,
	}, blocks, nil
}

func (s *Slack) replyError(m *SlackMessage, replier interface{}, err error, channelID string,
	attachments []*common.Attachment, actions []common.Action) (string, error) {

	s.logger.Error("Slack reply error: %s", err)
	key, _, err := s.reply(m, err.Error(), channelID, replier, attachments, actions, nil, nil, true)
	if err != nil {
		return "", err
	}
	return key.timestamp, nil
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

func (s *Slack) formBlocks(cmd common.Command, fields []common.Field, params common.ExecuteParams, u *SlackUser) ([]slack.Block, error) {

	blocks := []slack.Block{}
	blockID := common.UUID()

	// to do
	confirmationParams := make(common.ExecuteParams)
	for k, v := range params {
		confirmationParams[k] = v
	}

	for _, field := range fields {

		actionID := s.encodeActionID(blockID, slackFormFieldType, field.Name)

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
					loc, err := time.LoadLocation(u.timezone)
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
							loc, err := time.LoadLocation(u.timezone)
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
					loc, err := time.LoadLocation(u.timezone)
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
							loc, err := time.LoadLocation(u.timezone)
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
				groupName := s.findUserGroupNameByID(s.userGroups.items, def)
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
				groupName := s.findUserGroupNameByID(s.userGroups.items, v)
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

	submitActionID := s.encodeActionID(blockID, slackFormButtonType, slackSubmitAction)
	submit := slack.NewButtonBlockElement(submitActionID, "", slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonSubmitCaption, false, false))
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

	cancelActionID := s.encodeActionID(blockID, slackFormButtonType, slackCancelAction)
	cancel := slack.NewButtonBlockElement(cancelActionID, "", slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonCancelCaption, false, false))
	cancel.Style = slack.Style(s.options.ButtonCancelStyle)

	ab := slack.NewActionBlock(blockID, submit, cancel)
	blocks = append(blocks, ab)

	return blocks, nil
}

func (s *Slack) cacheReplyForm(m *SlackMessage, fields []common.Field, params common.ExecuteParams,
	replier *slacker.ResponseReplier) error {

	mThreadTS := m.key.threadTS
	opts := []slacker.PostOption{}
	replyInThread := !utils.IsEmpty(mThreadTS)
	if replyInThread {
		opts = append(opts, slacker.SetThreadTS(mThreadTS))
	}

	if utils.IsEmpty(m.botID) {
		opts = append(opts, slacker.SetEphemeral(m.userID()))
	}

	blocks, err := s.formBlocks(m.cmd, fields, params, m.user)
	if err != nil {
		return err
	}

	ts, err := replier.PostBlocks(m.key.channelID, blocks, opts...)
	if err != nil {
		return err
	}

	nParams := make(common.ExecuteParams)
	for _, v := range fields {
		nParams[v.Name] = v.Default
	}

	mNew := s.cloneMessage(m)
	mNew.originKey = m.key
	mNew.key = &SlackMessageKey{
		channelID: m.key.channelID,
		timestamp: ts,
		threadTS:  mThreadTS,
	}
	mNew.blocks = blocks
	mNew.params = nParams
	mNew.fields = fields

	s.putMessageToCache(mNew)

	return nil
}

func (s *Slack) cacheAskApproval(m *SlackMessage, message, channel string,
	approvalCmd common.Command, approvalParams common.ExecuteParams, replier *slacker.ResponseReplier) error {

	approval := approvalCmd.Approval()
	opts := []slacker.PostOption{}

	blocks := []slack.Block{}
	blockID := common.UUID()

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

		actionID := s.encodeActionID(blockID, slackApprovalFieldType, slackApprovalReasons)
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

		actionID := s.encodeActionID(blockID, slackApprovalFieldType, slackApprovalDescription)
		e := slack.NewPlainTextInputBlockElement(nil, actionID)
		e.Multiline = true
		l := slack.NewTextBlockObject(slack.PlainTextType, slackApprovalDescriptionCaption, false, false)
		b := slack.NewInputBlock("", l, nil, e)
		if b != nil {
			blocks = append(blocks, b)
		}
	}

	submitActionID := s.encodeActionID(blockID, slackApprovalButtonType, slackSubmitAction)
	submit := slack.NewButtonBlockElement(submitActionID, "", slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonApproveCaption, false, false))
	submit.Style = slack.Style(s.options.ButtonSubmitStyle)

	cancelActionID := s.encodeActionID(blockID, slackApprovalButtonType, slackCancelAction)
	cancel := slack.NewButtonBlockElement(cancelActionID, "", slack.NewTextBlockObject(slack.PlainTextType, s.options.ButtonRejectCaption, false, false))
	cancel.Style = slack.Style(s.options.ButtonCancelStyle)

	ab := slack.NewActionBlock(blockID, submit, cancel)
	blocks = append(blocks, ab)

	ts, err := replier.PostBlocks(channel, blocks, opts...)
	if err != nil {
		return err
	}

	mNew := s.cloneMessage(m)
	mNew.originKey = m.key
	mNew.key = &SlackMessageKey{
		channelID: channel,
		timestamp: ts,
	}
	mNew.cmd = approvalCmd
	mNew.params = approvalParams
	mNew.blocks = blocks

	s.putMessageToCache(mNew)
	return nil
}

func (s *Slack) mergeActions(one []common.Action, two []common.Action) []common.Action {

	actions := []common.Action{}

	for _, a1 := range one {
		found := false
		for _, a2 := range two {
			if a1.Name() == a2.Name() {
				found = true
				break
			}
		}
		if !found {
			actions = append(actions, a1)
		}
	}

	for _, a2 := range two {
		found := false
		for _, a1 := range actions {
			if a2.Name() == a1.Name() {
				found = true
				break
			}
		}
		if !found {
			actions = append(actions, a2)
		}
	}

	return actions
}

func (s *Slack) buildResponse(overwrite bool, list ...common.Response) *SlackResponse {

	r := &SlackResponse{}

	for _, response := range list {
		if response == nil {
			continue
		}
		if !r.visible || overwrite {
			r.visible = response.Visible()
		}
		if !r.error || overwrite {
			r.error = response.Error()
		}
		if !r.duration || overwrite {
			r.duration = response.Duration()
		}
		if !r.original || overwrite {
			r.original = response.Original()
		}
	}
	return r
}

func (s *Slack) messageResponses(m *SlackMessage, skip bool) []common.Response {

	r := []common.Response{}
	if m == nil {
		return r
	}
	if m.cmd != nil {
		cr := m.cmd.Response()
		if cr != nil {
			r1 := &SlackResponse{
				visible: cr.Visible(),
			}
			if !skip {
				r1.error = cr.Error()
				r1.duration = cr.Duration()
				r1.original = cr.Original()
			}
			r = append(r, r1)
		}
	}
	if m.wrapper != nil {
		cr := m.wrapper.Response()
		if cr != nil {
			r1 := &SlackResponse{
				visible: cr.Visible(),
			}
			if !skip {
				r1.error = cr.Error()
				r1.duration = cr.Duration()
				r1.original = cr.Original()
			}
			r = append(r, r1)
		}
	}
	return r
}

func (s *Slack) getMessageChannel(m *SlackMessage) string {

	// to think about it
	r := ""
	if m == nil || m.key == nil {
		return r
	}

	r = m.key.channelID
	if m.cmd != nil {
		rCmd := m.cmd.Channel()
		if !utils.IsEmpty(rCmd) {
			r = rCmd
		}
	}
	return r
}

func (s *Slack) cachePostUserCommand(m *SlackMessage, callback *slack.InteractionCallback, replier interface{},
	params common.ExecuteParams, action common.Action, response common.Response, overwrite bool) error {

	responseURL := ""
	blocks := []slack.Block{}
	if callback != nil {

		responseURL = callback.ResponseURL
		blocks = callback.Message.Blocks.BlockSet

		m.responseURL = responseURL
		m.blocks = blocks
		s.putMessageToCache(m)
	}

	start := time.Now()
	executor, message, attachments, actions, err := m.cmd.Execute(s, m, params, action)
	if err != nil {
		s.replyError(m, replier, err, "", attachments, nil)
		return err
	}
	if action == nil {
		actions = s.mergeActions(actions, m.cmd.Actions())
	}

	r := s.buildResponse(overwrite, response, executor.Response())

	var key *SlackMessageKey

	if !utils.IsEmpty(message) {

		k, blks, err := s.reply(m, message, s.getMessageChannel(m), replier, attachments, actions, r, &start, r.error)
		if err != nil {
			s.replyError(m, replier, err, "", attachments, nil)
			return err
		}
		key = k
		blocks = blks
	}

	mNew := s.cloneMessage(m)
	mNew.originKey = m.key
	mNew.key = key
	// set it to have next messages in the thread
	if mNew.key != nil && utils.IsEmpty(mNew.key.threadTS) {
		mNew.key.threadTS = mNew.key.timestamp
	}
	mNew.visible = r.visible
	mNew.responseURL = responseURL
	mNew.blocks = blocks
	mNew.actions = actions
	mNew.params = params

	s.putMessageToCache(mNew)

	return executor.After(mNew)
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

func (s *Slack) approvalNeeded(m *SlackMessage, cmd common.Command, params common.ExecuteParams) (string, string) {

	if cmd == nil {
		return "", ""
	}

	approval := cmd.Approval()
	if approval == nil {
		return "", ""
	}

	chl := approval.Channel(s, m, params)
	chl = strings.TrimSpace(chl)
	if utils.IsEmpty(chl) {
		chl = m.key.channelID
	}

	message := approval.Message(s, m, params)
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

func (s *Slack) findSlackUser(userID, botID string) *slack.User {

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

func (s *Slack) buildSlackUser(user *slack.User) *SlackUser {

	var u *SlackUser
	if user != nil {
		u = &SlackUser{
			id:       user.ID,
			name:     user.Name,
			timezone: user.TZ,
		}
		u.commands = s.listUserCommands(user.ID, s.userGroups.items)
	}
	return u
}

func (s *Slack) newSlackUser(userID, botID string) *SlackUser {
	return s.buildSlackUser(s.findSlackUser(userID, botID))
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
		// check first time, we don't need to track self commands
		if s.auth != nil && s.auth.UserID == event.UserID {
			return
		}

		key := &SlackMessageKey{
			channelID: event.ChannelID,
			timestamp: event.TimeStamp,
			threadTS:  event.ThreadTimeStamp,
		}
		s.addReaction(event.Type, key, s.options.ReactionDoing)

		u := s.newSlackUser(event.UserID, event.BotID)
		if u == nil {
			s.logger.Error("Slack couldn't process command from unknown user")
			return
		}

		// check second time, possiblu bot ID
		if s.auth != nil && s.auth.UserID == u.id {
			return
		}

		m := &SlackMessage{
			slack:     s,
			typ:       event.Type,
			cmdText:   event.Text,
			cmd:       cmd,
			wrapper:   nil,
			originKey: nil,
			key:       key,
			user:      u,
			caller:    u,
			botID:     event.BotID,
			//visible:     false,
			responseURL: "",
			blocks:      nil,
			actions:     nil,
			params:      nil,
			fields:      nil,
		}

		replier := cc.Response()

		if def == s.defaultDefinition {
			err := s.cachePostUserCommand(m, nil, replier, nil, nil, nil, false)
			if err != nil {
				s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
			}
			s.addRemoveReactions(m.typ, m.key, s.options.ReactionFailed, s.options.ReactionDoing)
			return
		}

		text := s.prepareInputText(event.Text, event.Type)

		wrapper := cmd.Wrapper()
		eParams, eCmd, eGroup, wrappedParams, wrappedCmd, wrappedGroup := s.findParams(wrapper, text)
		if eCmd == nil {
			eCmd = cmd
			eGroup = group
		}

		if wrappedCmd != nil {
			m.cmd = wrappedCmd
			m.wrapper = eCmd
		}

		cName := eCmd.Name()
		group = eGroup

		s.updateCounters(group, cName, text, u.id)

		groupName := cName
		if !utils.IsEmpty(group) {
			groupName = fmt.Sprintf("%s/%s", group, cName)
		}

		if eCmd.Permissions() {

			if def != s.defaultDefinition {
				if len(u.commands) > 0 && !utils.Contains(u.commands, groupName) {
					s.logger.Error("Slack user %s is not permitted to execute %s", u.id, groupName)
					s.removeReaction(m.typ, m.key, s.options.ReactionDoing)
					s.unsupportedCommandHandler(cc)
					return
				}
			}
		}

		eCommand := ""
		if eCmd != nil {
			eCommand = eCmd.Name()
			if !utils.IsEmpty(eCommand) {
				cmd = eCmd
			}
		}

		list := []string{common.FieldTypeSelect, common.FieldTypeMultiSelect, common.FieldTypeEdit}
		only := s.getFieldsByType(cmd, list)

		rFields := cmd.Fields(s, m, eParams, only)
		rParams := eParams

		approvalCmd := cmd
		approvalParams := rParams

		if wrapper {

			rCommand := ""
			if wrappedCmd != nil {
				rCommand = wrappedCmd.Name()
			} else {
				s.unsupportedCommandHandler(cc)
				return
			}
			rGroup := wrappedGroup

			wrapperGroupName := rCommand
			if utils.IsEmpty(wrapperGroupName) {
				wrapperGroupName = rGroup
			}
			if !utils.IsEmpty(rGroup) && !utils.IsEmpty(rCommand) {
				wrapperGroupName = fmt.Sprintf("%s/%s", rGroup, rCommand)
			}

			if wrappedCmd.Permissions() {

				if def != s.defaultDefinition {
					if len(u.commands) > 0 && !utils.Contains(u.commands, wrapperGroupName) {
						s.logger.Debug("Slack user %s is not permitted to execute %s", m.userID, wrapperGroupName)
						s.removeReaction(m.typ, m.key, s.options.ReactionDoing)
						s.unsupportedCommandHandler(cc)
						return
					}
				}
			}

			list := []string{common.FieldTypeSelect, common.FieldTypeMultiSelect, common.FieldTypeEdit}
			only := s.getFieldsByType(wrappedCmd, list)

			rFields = wrappedCmd.Fields(s, m, rParams, only)

			rParams = wrappedParams

			approvalCmd = wrappedCmd
			approvalParams = rParams
		}

		m.fields = rFields
		m.params = rParams
		s.putMessageToCache(m)

		if s.formNeeded(rFields, rParams) && u != nil {
			err := s.cacheReplyForm(m, rFields, rParams, replier)
			if err != nil {
				s.replyError(m, replier, err, "", nil, nil)
				s.addRemoveReactions(m.typ, m.key, s.options.ReactionFailed, s.options.ReactionDoing)
				return
			}
			s.addRemoveReactions(m.typ, m.key, s.options.ReactionForm, s.options.ReactionDoing)
			return
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

		message, channel := s.approvalNeeded(m, approvalCmd, approvalParams)
		if !utils.IsEmpty(message) {
			s.addRemoveReactions(m.typ, m.key, s.options.ReactionApproval, s.options.ReactionDoing)
			err := s.cacheAskApproval(m, message, channel, approvalCmd, approvalParams, replier)
			if err != nil {
				s.replyError(m, replier, err, "", nil, nil)
				s.addRemoveReactions(m.typ, m.key, s.options.ReactionFailed, s.options.ReactionApproval)
				return
			}
			return
		}

		rParams = common.MergeInterfaceMaps(eParams, rParams)
		r := s.buildResponse(false, s.messageResponses(m, false)...)
		err := s.cachePostUserCommand(m, nil, replier, rParams, nil, r, false)
		if err != nil {
			s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
			s.addRemoveReactions(m.typ, m.key, s.options.ReactionFailed, s.options.ReactionDoing)
			return
		}
		s.addRemoveReactions(m.typ, m.key, s.options.ReactionDone, s.options.ReactionDoing)
	}
	return def
}

func (s *Slack) removeMessage(m *SlackMessage) {
	if m == nil || m.key == nil {
		return
	}
	s.client.SlackClient().PostEphemeral(m.key.channelID, m.userID(),
		slack.MsgOptionReplaceOriginal(m.responseURL),
		slack.MsgOptionDeleteOriginal(m.responseURL),
	)
}

func (s *Slack) replaceMessage(m *SlackMessage, blocks []slack.Block) (string, error) {
	if m == nil || m.key == nil {
		return "", nil
	}
	return s.client.SlackClient().PostEphemeral(m.key.channelID, m.userID(),
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionReplaceOriginal(m.responseURL),
	)
}

func (s *Slack) replaceApprovalMessage(m *SlackMessage, message string) (string, error) {

	blocks := []slack.Block{}
	for _, block := range m.blocks {

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
	return s.replaceMessage(m, blocks)
}

// this method primarily used in custom command executions
func (s *Slack) Command(channel, text string, user common.User, parent common.Message, response common.Response) error {

	channelID := channel
	threadTS := ""
	userID := "unknown"

	r := s.buildResponse(true, response)

	var mOrigin *SlackMessage
	if !utils.IsEmpty(parent) {
		m, ok := parent.(*SlackMessage)
		if ok {
			// if key is not set, it means that message is not posted yet
			// so we need to find it in cache
			if m.key == nil {
				mOrigin = m
			} else {
				mOrigin = s.findMessageInCache(m.key)
			}
			if mOrigin != nil && mOrigin.key != nil {
				if utils.IsEmpty(channelID) {
					channelID = mOrigin.key.channelID
				}
				threadTS = mOrigin.key.threadTS
			}
			r = s.buildResponse(false, append(s.messageResponses(m, true), response)...)
		}
	}

	var mUser *SlackUser
	if !utils.IsEmpty(user) {
		u, ok := user.(*SlackUser)
		if ok {
			mUser = u
		}
		userID = user.ID()
	}

	fText := s.prepareInputText(text, slackMessageType)
	params, cmd, group, _, _, _ := s.findParams(false, fText)
	if cmd == nil {
		s.logger.Debug("Slack command not found for text: %s", text)
		return nil
	}

	groupName := cmd.Name()
	if !utils.IsEmpty(group) {
		groupName = fmt.Sprintf("%s/%s", group, groupName)
	}

	if !utils.IsEmpty(user) {
		userID := user.ID()
		if !utils.Contains(user.Commands(), groupName) {
			s.logger.Debug("Slack command user %s is not permitted to execute %s", userID, groupName)
			return nil
		}
	}

	fields := cmd.Fields(s, parent, params, nil)
	if s.formNeeded(fields, params) {
		s.logger.Debug("Slack command %s has no support for interaction mode", groupName)
		return nil
	}

	var m *SlackMessage
	key := &SlackMessageKey{
		channelID: channelID,
		threadTS:  threadTS,
	}

	if !utils.IsEmpty(mOrigin) {
		m = s.cloneMessage(mOrigin)
		m.typ = slackMessageType
		m.cmdText = fText
		m.cmd = cmd
		m.key = key
		m.originKey = mOrigin.key
		m.fields = fields
	} else {
		m = &SlackMessage{
			slack:     s,
			typ:       slackMessageType,
			cmdText:   fText,
			cmd:       cmd,
			wrapper:   nil,
			originKey: nil,
			key:       key,
			user:      mUser,
			caller:    mUser,
			botID:     "",
			//visible:     false,
			responseURL: "",
			blocks:      nil,
			actions:     nil,
			params:      params,
			fields:      fields,
		}
	}

	err := s.cachePostUserCommand(m, nil, nil, params, nil, r, true)
	if err != nil {
		s.logger.Error("Slack command %s couldn't post from %s: %s", groupName, userID, err)
		return err
	}

	return nil
}

// this method is needed to post custom messages
func (s *Slack) PostMessage(channel string, message string, attachments []*common.Attachment, actions []common.Action,
	user common.User, parent common.Message, response common.Response) (string, error) {

	channelID := channel
	threadTS := ""
	userID := ""

	r := s.buildResponse(true, response)

	var mOrigin *SlackMessage
	if !utils.IsEmpty(parent) {
		m, ok := parent.(*SlackMessage)
		if ok {
			// if key is not set, it means that message is not posted yet
			// so we need to find it in cache
			if m.key == nil {
				mOrigin = m
			} else {
				mOrigin = s.findMessageInCache(m.key)
			}
			if mOrigin != nil && mOrigin.key != nil {
				if utils.IsEmpty(channelID) {
					channelID = mOrigin.key.channelID
				}
				threadTS = mOrigin.key.threadTS
			}
			r = s.buildResponse(false, append(s.messageResponses(mOrigin, true), response)...)
		}
	}

	var mUser *SlackUser
	if !utils.IsEmpty(user) {
		u, ok := user.(*SlackUser)
		if ok {
			mUser = u
		}
		userID = user.ID()
	}

	atts, err := s.buildAttachmentBlocks(attachments)
	if err != nil {
		return "", err
	}

	blocks := []slack.Block{}
	blocks = append(blocks, slack.NewSectionBlock(
		slack.NewTextBlockObject(slack.MarkdownType, message, false, false),
		[]*slack.TextBlockObject{}, nil,
	))

	actBlocks := s.buildActionBlocks(actions, true)
	if len(actBlocks) > 0 {
		blocks = append(blocks, actBlocks...)
	}

	options := []slack.MsgOption{}
	options = append(options, slack.MsgOptionBlocks(blocks...), slack.MsgOptionAttachments(atts...))
	options = append(options, slack.MsgOptionDisableLinkUnfurl())

	if !utils.IsEmpty(threadTS) {
		options = append(options, slack.MsgOptionTS(threadTS))
	}

	if !r.visible && !utils.IsEmpty(userID) {
		options = append(options, slack.MsgOptionPostEphemeral(userID))
	}

	client := s.client.SlackClient()
	_, ts, err := client.PostMessage(channelID, options...)
	if err != nil {
		return "", err
	}

	/*key, blocks, err := s.reply(mOrigin, message, channelID, replier, attachments, actions, r, &start, r.error)
	if err != nil {
		return "", err
	}

	var m *SlackMessage*/

	var m *SlackMessage
	key := &SlackMessageKey{
		channelID: channelID,
		timestamp: ts,
		threadTS:  threadTS,
	}

	if !utils.IsEmpty(mOrigin) {
		m = s.cloneMessage(mOrigin)
		m.key = key
		m.originKey = mOrigin.key
		m.blocks = blocks
		m.actions = actions
		s.putMessageToCache(m)
	} else {
		m = &SlackMessage{
			slack:       s,
			typ:         slackMessageType,
			cmdText:     "",
			cmd:         nil,
			wrapper:     nil,
			originKey:   nil,
			key:         key,
			user:        mUser,
			caller:      mUser,
			botID:       "",
			visible:     r.visible,
			responseURL: "",
			blocks:      blocks,
			actions:     actions,
			params:      nil,
			fields:      nil,
		}
		s.putMessageToCache(m)
	}
	return ts, nil
}

func (s *Slack) getActionValue(field *common.Field, state slack.BlockAction) interface{} {

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
				v2 = s.findUserGroupIDByName(s.userGroups.items, v2)
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
					v3 = s.findUserGroupIDByName(s.userGroups.items, v3)
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

func (s *Slack) handleFormField(ctx *slacker.InteractionContext, m *SlackMessage, action *slack.BlockAction, name string) bool {

	callback := ctx.Callback()
	if m.cmd == nil {
		return false
	}

	// find all fields that depend on name
	deps := []string{}
	skip := []common.FieldType{common.FieldTypeDynamicSelect, common.FieldTypeDynamicMultiSelect}

	allFields := m.cmd.Fields(s, m, nil, nil)
	for _, field := range allFields {
		if utils.Contains(field.Dependencies, name) && !utils.Contains(skip, field.Type) {
			deps = append(deps, field.Name)
		}
	}

	params := make(common.ExecuteParams)
	params[name] = action.Value

	for _, v1 := range callback.BlockActionState.Values {
		for k2, v2 := range v1 {
			_, _, n2 := s.decodeActionID(k2)
			if utils.IsEmpty(n2) {
				continue
			}
			field := s.findField(m.cmd.Fields(s, nil, nil, nil), n2)
			params[n2] = s.getActionValue(field, v2)
		}
	}

	// get dependent fields
	depFields := m.cmd.Fields(s, m, params, deps)
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
	cache := m.params
	for k, v := range cache {
		if _, ok := cParams[k]; ok {
			continue
		}
		cParams[k] = v
	}
	m.params = cParams
	m.responseURL = callback.ResponseURL
	s.putMessageToCache(m)

	if len(deps) == 0 {
		return false
	}

	blocks, err := s.formBlocks(m.cmd, allFields, params, m.user)
	if err != nil {
		s.logger.Error("Slack couldn't generate form blocks, error: %s", err)
		return false
	}

	options := []slack.MsgOption{}
	//options = append(options, slack.MsgOptionBlocks(blocks...), slack.MsgOptionReplaceOriginal(m.responseURL), slack.MsgOptionPostEphemeral(m.userID)) // section doesn't work
	options = append(options, slack.MsgOptionBlocks(blocks...), slack.MsgOptionReplaceOriginal(m.responseURL), slack.MsgOptionTS(m.key.threadTS)) // section works :(

	_, _, _, err = s.client.SlackClient().UpdateMessage(m.key.channelID, m.key.timestamp, options...)
	if err != nil {
		s.logger.Error("Slack couldn't update form message, error: %s", err)
		return false
	}
	return true
}

func (s *Slack) handleFormButtonReaction(ctx *slacker.InteractionContext, m *SlackMessage, name, reaction string) bool {

	callback := ctx.Callback()
	if m.cmd == nil {
		return false
	}

	m.responseURL = callback.ResponseURL

	params := make(common.ExecuteParams)
	switch name {
	case slackSubmitAction:

		states := callback.BlockActionState
		if states != nil && len(states.Values) > 0 {

			for _, v1 := range states.Values {
				for k2, v2 := range v1 {
					_, _, n2 := s.decodeActionID(k2)
					if utils.IsEmpty(n2) {
						continue
					}
					field := s.findField(m.cmd.Fields(s, nil, nil, nil), n2)
					params[n2] = s.getActionValue(field, v2)
				}
			}
		}

		// check cache params
		cParams := params
		cache := m.params
		for k, v := range cache {
			if _, ok := cParams[k]; ok {
				continue
			}
			cParams[k] = v
		}
		params = cParams
		m.params = params
		s.putMessageToCache(m)

		// check approval
		message, channel := s.approvalNeeded(m, m.cmd, params)
		if !utils.IsEmpty(message) {

			replier := ctx.Response()
			s.addRemoveReactions(m.typ, m.originKey, s.options.ReactionApproval, reaction)

			err := s.cacheAskApproval(m, message, channel, m.cmd, params, replier)
			if err != nil {
				s.replyError(m, replier, err, "", nil, nil)
				s.addRemoveReactions(m.typ, m.originKey, s.options.ReactionFailed, s.options.ReactionApproval)
				return false
			}
			s.removeMessage(m)
			return true
		}

		s.removeMessage(m)
		s.addRemoveReactions(m.typ, m.originKey, s.options.ReactionDoing, reaction)
		s.executeCommandAfterApprovalReaction(ctx, m, m.originKey, params, s.options.ReactionDoing)

	default:
		s.removeMessage(m)
		s.addRemoveReactions(m.typ, m.originKey, s.options.ReactionFailed, reaction)
	}
	return true
}

func (s *Slack) executeCommandAfterApprovalReaction(ctx *slacker.InteractionContext, m *SlackMessage, reactionKey *SlackMessageKey, params common.ExecuteParams, reaction string) bool {

	callback := ctx.Callback()
	if m.cmd == nil {
		return false
	}

	r := s.buildResponse(false, s.messageResponses(m, false)...)

	err := s.cachePostUserCommand(m, callback, ctx.Response(), params, nil, r, false)
	if err != nil {
		s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
		s.addRemoveReactions(m.typ, reactionKey, s.options.ReactionFailed, reaction)
		return false
	}
	s.addRemoveReactions(m.typ, reactionKey, s.options.ReactionDone, reaction)
	return true
}

func (s *Slack) cacheHandleApprovalButtonReaction(ctx *slacker.InteractionContext, m *SlackMessage, name, reaction string) bool {

	callback := ctx.Callback()
	if m.cmd == nil {
		return false
	}

	approval := m.cmd.Approval()
	if approval == nil {
		return false
	}

	mInit := s.findInitMessageInCache(m)
	if mInit == nil {
		return false
	}

	if !s.options.ApprovalAny {
		if callback.User.ID == m.userID() {
			s.logger.Error("Slack same user cannot approve its action")
			return false
		}
	}

	approvedRejected := ""

	mReaction := common.IfDef(name == slackSubmitAction, s.options.ReactionApproved, s.options.ReactionRejected)
	mDef := common.IfDef(name == slackSubmitAction, s.options.ApprovedMessage, s.options.RejectedMessage)
	if !utils.IsEmpty(mDef) {
		user := fmt.Sprintf("<@%s>", callback.User.ID)
		approvedRejected = fmt.Sprintf(mDef.(string), user, time.Now().Format("15:04:05"))
		approvedRejected = fmt.Sprintf(":%s: %s", mReaction, approvedRejected)
	}

	m.responseURL = callback.ResponseURL
	_, err := s.replaceApprovalMessage(m, approvedRejected)
	if err != nil {
		s.logger.Error("Slack couldn't update approval message, error: %s", err)
		s.addRemoveReactions(mInit.typ, mInit.key, s.options.ReactionFailed, reaction)
		return false
	}

	reasons := ""
	description := ""

	for _, v1 := range callback.BlockActionState.Values {
		for k2, v2 := range v1 {

			_, _, n := s.decodeActionID(k2)
			if utils.IsEmpty(n) {
				continue
			}
			switch n {
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
		return false
	}

	r := &SlackResponse{
		visible: approval.Visible(),
	}

	key, blocks, err := s.reply(mInit, message, "", ctx.Response(), nil, nil, r, nil, false)
	if err != nil {
		s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
		s.addRemoveReactions(mInit.typ, mInit.key, s.options.ReactionFailed, reaction)
		return false
	}

	mNew := s.cloneMessage(mInit)
	mNew.originKey = m.key
	mNew.key = key
	mNew.blocks = blocks
	s.putMessageToCache(mNew)

	if name == slackSubmitAction {
		mParent := s.findParentMessageInCache(m)
		if mParent == nil {
			return false
		}
		return s.executeCommandAfterApprovalReaction(ctx, mInit, mInit.key, mParent.params, reaction)
	}
	s.addRemoveReactions(mInit.typ, mInit.key, s.options.ReactionFailed, reaction)
	return false
}

func (s *Slack) cacheHandleActionButton(ctx *slacker.InteractionContext, m *SlackMessage, name string) bool {

	callback := ctx.Callback()
	if m.cmd == nil && m.key == nil {
		return false
	}

	// set thread timestamp to reply in thread
	if utils.IsEmpty(m.key.threadTS) {
		m.key.threadTS = callback.Container.ThreadTs
	}

	if utils.IsEmpty(m.key.threadTS) {
		m.key.threadTS = m.key.timestamp
	}

	var action common.Action
	for _, a := range m.actions {
		if a.Name() == name {
			action = a
			break
		}
	}

	if action == nil {
		s.logger.Error("Slack action %s is not defined.", name)
		return false
	}

	r := s.buildResponse(false, s.messageResponses(m, false)...)

	err := s.cachePostUserCommand(m, callback, ctx.Response(), m.params, action, r, true)
	if err != nil {
		s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
		return false
	}
	return true
}

func (s *Slack) handleBlockActions(ctx *slacker.InteractionContext) {

	callback := ctx.Callback()

	key := &SlackMessageKey{
		channelID: callback.Container.ChannelID,
		timestamp: callback.Container.MessageTs,
		threadTS:  callback.Container.ThreadTs,
	}

	reaction := s.options.ReactionForm

	actions := callback.ActionCallback.BlockActions
	if len(actions) == 0 {
		s.logger.Error("Slack actions are not defined.")
		s.removeReaction(callback.Container.Type, key, reaction)
		return
	}

	action := actions[0]
	if action == nil {
		s.logger.Error("Slack default action is not defined.")
		s.removeReaction(callback.Container.Type, key, reaction)
		return
	}

	mCache := s.findMessageInCache(key)
	if mCache == nil {
		s.logger.Error("Slack message is not found in cache.")
		s.removeReaction(callback.Container.Type, key, reaction)
		return
	}
	mCache.caller = s.buildSlackUser(&callback.User)
	s.putMessageToCache(mCache)

	_, typ, name := s.decodeActionID(action.ActionID)
	if utils.IsEmpty(name) {
		s.logger.Error("Slack action name is empty.")
		s.removeReaction(callback.Container.Type, key, reaction)
		return
	}

	switch typ {
	case slackFormFieldType:
		s.handleFormField(ctx, mCache, action, name)
	case slackFormButtonType:
		s.handleFormButtonReaction(ctx, mCache, name, reaction)
	case slackApprovalFieldType:
		// we don't track it, cause no followig actions are needed
	case slackApprovalButtonType:
		s.cacheHandleApprovalButtonReaction(ctx, mCache, name, s.options.ReactionApproval)
	case slackActionButtonType:
		s.cacheHandleActionButton(ctx, mCache, name)
	}
}

func (s *Slack) handleBlockSuggestion(ctx *slacker.InteractionContext, req *socketmode.Request) {

	callback := ctx.Callback()

	if utils.IsEmpty(callback.Value) {
		return
	}

	_, _, name := s.decodeActionID(callback.ActionID)
	if utils.IsEmpty(name) {
		return
	}

	key := &SlackMessageKey{
		channelID: callback.Container.ChannelID,
		timestamp: callback.Container.MessageTs,
		threadTS:  callback.Container.ThreadTs,
	}

	m := s.findMessageInCache(key)
	if m == nil {
		return
	}

	if m.cmd == nil {
		return
	}

	params := make(common.ExecuteParams)
	cache := m.params
	for k, v := range cache {
		if _, ok := params[k]; ok {
			continue
		}
		params[k] = v
	}

	options := []*slack.OptionBlockObject{}
	value := callback.Value
	if utils.IsEmpty(value) {
		return
	}
	params[name] = value

	fields := m.cmd.Fields(s, m, params, []string{name})
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
		s.handleBlockActions(ctx)
	case slack.InteractionTypeBlockSuggestion:
		s.handleBlockSuggestion(ctx, req)
	}
}

func (s *Slack) unsupportedEventnHandler(event socketmode.Event) {

	switch event.Type {
	default:
		s.logger.Debug("Slack unsupported event type: %s", event.Type)
	}
}

func (s *Slack) newInteraction(name, group string) *slacker.InteractionDefinition {

	def := &slacker.InteractionDefinition{
		InteractionID: fmt.Sprintf("%s/%s", name, group),
		Type:          slack.InteractionTypeBlockActions,
	}
	def.Handler = func(ctx *slacker.InteractionContext, req *socketmode.Request) {
		s.handleBlockActions(ctx)
	}
	return def
}

func (s *Slack) newJob(cmd common.Command) *slacker.JobDefinition {

	cName := cmd.Name()

	def := &slacker.JobDefinition{
		CronExpression: cmd.Schedule(),
		Name:           cName,
		Description:    cmd.Description(),
		HideHelp:       true,
	}
	def.Handler = func(cc *slacker.JobContext) {

		channelID := s.options.PublicChannel
		cmdChannelID := cmd.Channel()
		if !utils.IsEmpty(cmdChannelID) {
			channelID = cmdChannelID
		}

		m := &SlackMessage{
			slack: s,
			cmd:   cmd,
			key: &SlackMessageKey{
				channelID: channelID,
			},
		}

		start := time.Now()
		executor, message, attachments, actions, err := cmd.Execute(s, m, nil, nil)
		if err != nil {
			s.logger.Error("Slack couldn't execute job %s: %s", cName, err)
			return
		}

		if utils.IsEmpty(strings.TrimSpace(message)) {
			return
		}

		r := &SlackResponse{}
		response := executor.Response()
		if !utils.IsEmpty(response) {
			r.visible = response.Visible()
			r.error = response.Error()
		}

		key, blocks, err := s.reply(m, message, channelID, cc.Response(), attachments, actions, r, &start, r.error)
		if err != nil {
			s.logger.Error("Slack couldn't post from %s: %s", m.userID, err)
			return
		}
		mNew := s.cloneMessage(m)
		mNew.key = key
		mNew.blocks = blocks
		mNew.actions = actions
		mNew.visible = r.visible
		s.putMessageToCache(mNew)

		err = executor.After(mNew)
		if err != nil {
			s.logger.Error("Slack couldn't execute job %s after: %s", cName, err)
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
				client.AddInteraction(s.newInteraction(c.Name(), ""))
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
				client.AddInteraction(s.newInteraction(c.Name(), pName))
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
					client.AddInteraction(s.newInteraction(c.Name(), ""))
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
			client.AddJob(s.newJob(c))
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

	s.userGroups.slack = s
	s.userGroups.refresh()
	if s.options.UserGroupsInterval > 0 {
		common.Schedule(s.userGroups.refresh, time.Duration(s.options.UserGroupsInterval)*time.Second)
	}

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

	messagesOpts := []ttlcache.Option[string, *SlackMessage]{}
	messagesOpts = append(messagesOpts, ttlcache.WithTTL[string, *SlackMessage](ttl))
	messages := ttlcache.New[string, *SlackMessage](messagesOpts...)
	go messages.Start()

	return &Slack{
		options:    options,
		processors: processors,
		logger:     observability.Logs(),
		meter:      observability.Metrics(),
		messages:   messages,
	}
}
