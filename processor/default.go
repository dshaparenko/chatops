package processor

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devopsext/chatops/common"
	"github.com/devopsext/chatops/vendors"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"

	"golang.org/x/sync/errgroup"

	"github.com/jinzhu/copier"
	"gopkg.in/yaml.v2"
)

type DefaultRunbookStepResult struct {
	ID           string
	Text         string
	Attachements []*common.Attachment
	Actions      []common.Action
	Error        error
}

type DefaultRunbookStepResultFunc = func(result *DefaultRunbookStepResult, parent common.Message) error

type DefaultRunbookStep struct {
	ID       string
	Step     string
	Template string
	Command  string
	Disabled bool
	Pipeline []*DefaultRunbookStep
}

type DefaultRunbookConfig struct {
	Description string
	Params      []string
	Pipeline    []*DefaultRunbookStep
}

type DefaultRunbook struct {
	name           string
	path           string
	command        *DefaultCommand
	config         *DefaultRunbookConfig
	parentExecutor *DefaultExecutor
}

type DefaultPostKind = int

const (
	DefaultPostKindTemplate = 0
	DefaultPostKindCommand  = 1
	DefaultPostKindRunbook  = 2
)

type DefaultPost struct {
	Name string
	Path string
	Obj  interface{}
	Kind DefaultPostKind
}

type DefaultExecutor struct {
	command     *DefaultCommand
	visible     *bool
	error       *bool
	attachments *sync.Map
	actions     *sync.Map
	posts       *sync.Map
	bot         common.Bot
	params      common.ExecuteParams
	message     common.Message
	template    *toolsRender.TextTemplate
	action      common.Action
}

type DefaultFieldWrapper struct {
	*DefaultField
	children []*DefaultFieldWrapper
	parent   *DefaultFieldWrapper
}

type DefaultFieldExecutor struct {
	command  *DefaultCommand
	fields   *sync.Map
	bot      common.Bot
	params   common.ExecuteParams
	message  common.Message
	template *toolsRender.TextTemplate
	field    *DefaultFieldWrapper
	funcs    map[string]any
}

type DefaultRunbookTemplateExecutor = DefaultExecutor

type DefaultRunbookCommandExecutor struct {
	runbookExecutor *DefaultRunbookExecutor
	bot             common.Bot
	params          common.ExecuteParams
	message         common.Message
	command         string
}

type DefaultRunbookExecutor struct {
	templateExecutor *DefaultRunbookTemplateExecutor
	commandExecutor  *DefaultRunbookCommandExecutor
	runbook          *DefaultRunbook
	step             *DefaultRunbookStep
	description      string
}

type DefaultOptions struct {
	CommandsDir  string
	TemplatesDir string
	RunbooksDir  string
	CommandExt   string
	ConfigExt    string
	Description  string
	Error        string
}

type DefaultResponse struct {
	Visible  *bool
	Original *bool
	Duration *bool
}

type DefaultApproval struct {
	Channel     string
	Template    string
	Reasons     []string
	Description bool
	Visible     bool
	Disabled    bool
}

type DefaultField struct {
	Name         string
	Type         common.FieldType
	Label        string
	Values       []string
	Default      string
	Required     bool
	Template     string
	Dependencies []string
	Hint         string
	Filter       string
	Value        string
	Visible      *bool
}

type DefaultAction struct {
	Name     string
	Label    string
	Template string
	Style    string
}

type DefaultCommandConfig struct {
	Description  string
	Params       []string
	Aliases      []string
	Response     DefaultResponse
	Fields       []*DefaultField
	Actions      []*DefaultAction
	Priority     int
	Wrapper      bool
	Schedule     string
	Channel      string
	Confirmation string
	Approval     *DefaultApproval
	Permissions  *bool
}

type DefaultCommandResponse struct {
	command *DefaultCommand
}

type DefaultCommandApproval struct {
	command *DefaultCommand
}

type DefaultCommandAction struct {
	command  *DefaultCommand
	name     string
	label    string
	template string
	style    string
}

type DefaultCommand struct {
	name      string
	path      string
	config    *DefaultCommandConfig
	processor *Default
	logger    sreCommon.Logger
}

type Default struct {
	name          string
	options       DefaultOptions
	processors    *common.Processors
	commands      []common.Command
	meter         sreCommon.Meter
	observability *common.Observability
}

// Default executor
// common.Response

func (de *DefaultExecutor) Visible() bool {

	if de.visible != nil {
		return *de.visible
	}
	if !utils.IsEmpty(de.message) {
		return de.message.Visible()
	}
	return false
}

func (de *DefaultExecutor) Error() bool {
	if de.error != nil {
		return *de.error
	}
	return false
}

/*func (de *DefaultExecutor) Reaction() bool {
	if de.reaction != nil {
		return *de.reaction
	}
	return false
}*/

func (de *DefaultExecutor) Duration() bool {
	if de.command.config != nil {
		d := de.command.config.Response.Duration
		if d != nil {
			return *d
		}
	}
	return false
}

func (de *DefaultExecutor) Original() bool {
	if de.command.config != nil {
		o := de.command.config.Response.Original
		if o != nil {
			return *o
		}
	}
	return false
}

func (de *DefaultExecutor) Response() common.Response {
	return de
}

func (de *DefaultExecutor) Approval() common.Approval {
	// to do
	return nil
}

func (de *DefaultExecutor) filePath(dir, fileName string) string {
	return fmt.Sprintf("%s%s%s", dir, string(os.PathSeparator), fileName)
}

func (de *DefaultExecutor) fPostFile(path string, obj interface{}, kind DefaultPostKind) string {

	gid := utils.GoRoutineID()
	var posts []*DefaultPost

	r, ok := de.posts.Load(gid)
	if ok {
		posts = r.([]*DefaultPost)
	}

	ext := filepath.Ext(path)
	name := strings.TrimSuffix(path, ext)

	posts = append(posts, &DefaultPost{
		Name: filepath.Base(name),
		Path: path,
		Obj:  obj,
		Kind: kind,
	})
	de.posts.Store(gid, posts)
	return ""
}

func (de *DefaultExecutor) fPostCommand(fileName string, obj interface{}) string {
	s := de.filePath(de.command.processor.options.CommandsDir, fileName)
	return de.fPostFile(s, obj, DefaultPostKindCommand)
}

func (de *DefaultExecutor) fPostTemplate(fileName string, obj interface{}) string {
	s := de.filePath(de.command.processor.options.TemplatesDir, fileName)
	return de.fPostFile(s, obj, DefaultPostKindTemplate)
}

func (de *DefaultExecutor) fPostBook(fileName string, obj interface{}) string {
	s := de.filePath(de.command.processor.options.RunbooksDir, fileName)
	return de.fPostFile(s, obj, DefaultPostKindRunbook)
}

func (de *DefaultExecutor) fCreateAttachment(title, text string, data interface{}, typ string) interface{} {

	dBytes, ok := data.([]byte)
	if !ok {
		s := fmt.Sprintf("%v", data)
		dBytes = []byte(s)
	}

	att := &common.Attachment{
		Title: title,
		Text:  text,
		Data:  dBytes,
		Type:  common.AttachmentType(typ),
	}
	return att
}

func (de *DefaultExecutor) fAddAttachment(title, text string, data interface{}, typ string) string {

	gid := utils.GoRoutineID()
	var atts []*common.Attachment

	r, ok := de.attachments.Load(gid)
	if ok {
		atts = r.([]*common.Attachment)
	}

	dBytes, ok := data.([]byte)
	if !ok {
		s := fmt.Sprintf("%v", data)
		dBytes = []byte(s)
	}

	att := &common.Attachment{
		Title: title,
		Text:  text,
		Data:  dBytes,
		Type:  common.AttachmentType(typ),
	}
	atts = append(atts, att)
	de.attachments.Store(gid, atts)
	return ""
}

func (de *DefaultExecutor) fAddAction(name, label, template, style string) string {

	gid := utils.GoRoutineID()
	var acts []*DefaultCommandAction

	r, ok := de.actions.Load(gid)
	if ok {
		acts = r.([]*DefaultCommandAction)
	}

	act := &DefaultCommandAction{
		command:  de.command,
		name:     name,
		label:    label,
		template: template,
		style:    style,
	}
	acts = append(acts, act)
	de.actions.Store(gid, acts)
	return ""
}

func (de *DefaultExecutor) fAddActionToMessage(channelID, messageID, name, label, template, style string) string {

	action := &DefaultCommandAction{
		command:  de.command,
		name:     name,
		label:    label,
		template: template,
		style:    style,
	}
	err := de.bot.AddAction(channelID, messageID, action)
	if err != nil {
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fAddActionsToMessage(channelID, messageID string, list []interface{}) string {

	actions := []common.Action{}

	for _, item := range list {

		mi, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		name := ""
		n := mi["name"]
		if n != nil {
			name, _ = n.(string)
		}
		if utils.IsEmpty(name) {
			continue
		}

		template := ""
		t := mi["template"]
		if n != nil {
			template, _ = t.(string)
		}

		label := ""
		l := mi["label"]
		if l != nil {
			label, _ = l.(string)
		}

		style := ""
		s := mi["style"]
		if s != nil {
			style, _ = s.(string)
		}

		action := &DefaultCommandAction{
			command:  de.command,
			name:     name,
			label:    label,
			template: template,
			style:    style,
		}
		actions = append(actions, action)
	}

	err := de.bot.AddActions(channelID, messageID, actions)
	if err != nil {
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fRemoveActionFromMessage(channelID, messageID, name string) string {

	err := de.bot.RemoveAction(channelID, messageID, name)
	if err != nil {
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fClearActionsFromMessage(channelID, messageID string) string {

	err := de.bot.ClearActions(channelID, messageID)
	if err != nil {
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fAddFile(name string, data interface{}, typ string) string {
	return ""
}

func (de *DefaultExecutor) fRunFile(path string, obj interface{}) (string, error) {
	if !utils.FileExists(path) {
		return "", fmt.Errorf("Default couldn't find file %s", path)
	}
	return de.template.TemplateRenderFile(path, obj)
}

func (de *DefaultExecutor) fRunCommand(fileName string, obj interface{}) (string, error) {
	s := de.filePath(de.command.processor.options.CommandsDir, fileName)
	if !utils.FileExists(s) {
		return "", fmt.Errorf("Default couldn't find command file %s", s)
	}
	return de.template.TemplateRenderFile(s, obj)
}

func (de *DefaultExecutor) fRunTemplate(fileName string, obj interface{}) (string, error) {
	s := de.filePath(de.command.processor.options.TemplatesDir, fileName)
	if !utils.FileExists(s) {
		return "", fmt.Errorf("Default couldn't find template file %s", s)
	}
	return de.template.TemplateRenderFile(s, obj)
}

func (de *DefaultExecutor) fRunBook(fileName string, obj interface{}) (string, error) {

	s := de.filePath(de.command.processor.options.RunbooksDir, fileName)
	if !utils.FileExists(s) {
		return "", fmt.Errorf("Default couldn't find runbook file %s", s)
	}

	ext := filepath.Ext(fileName)
	name := strings.TrimSuffix(fileName, ext)

	rb, err := NewRunbook(name, s, de.command, de)
	if err != nil {
		return "", err
	}

	err = rb.Execute(de.bot, de.message, obj, de.runbookAfterCallback, true)
	if err != nil {
		return "", err
	}
	return "", nil
}

func (de *DefaultExecutor) fSendMessageEx(message, channels string, params map[string]interface{}, parent string) (string, error) {

	if utils.IsEmpty(message) {
		return "", fmt.Errorf("SendMessageEx err => %s", "empty message")
	}

	if utils.IsEmpty(channels) {
		return "", fmt.Errorf("SendMessageEx err => %s", "no channels")
	}

	chnls := strings.Split(channels, ",")
	chnls = common.RemoveEmptyStrings(chnls)

	if len(chnls) == 0 {
		return "", fmt.Errorf("SendMessageEx err => %s", "no channels")
	}

	atts := []*common.Attachment{}
	if len(params) > 0 {
		attachment, ok := params["attachment"].(*common.Attachment)
		if ok {
			atts = append(atts, attachment)
		}
		attachments, ok := params["attachments"].([]interface{})
		if ok {
			for _, a := range attachments {
				attachment, ok := a.(*common.Attachment)
				if ok {
					atts = append(atts, attachment)
				}
			}
		}
	}

	acts := []common.Action{}
	if len(params) > 0 {
		action, ok := params["action"].(common.Action)
		if ok {
			acts = append(acts, action)
		}
		actions, ok := params["actions"].([]interface{})
		if ok {
			for _, a := range actions {
				action, ok := a.(common.Action)
				if ok {
					acts = append(acts, action)
				}
			}
		}
	}

	var user common.User
	if !utils.IsEmpty(de.message) {
		user = de.message.User()
	}

	var msg common.Message
	if !utils.IsEmpty(parent) {
		msg = de.message
	}

	if !utils.IsEmpty(msg) {
		msg.SetParentID(parent)
	}

	var err error
	var timeStamp string
	for _, ch := range chnls {
		timeStamp, err = de.bot.PostMessage(ch, message, atts, acts, user, msg, de.Response())
		if err != nil {
			de.command.logger.Error(err)
		}
	}

	return timeStamp, err
}

func (de *DefaultExecutor) fSendMessage(message, channels string) (string, error) {
	return de.fSendMessageEx(message, channels, nil, "")
}

func (de *DefaultExecutor) fSendMessageByParent(message, channels, parentID string) (string, error) {
	return de.fSendMessageEx(message, channels, nil, parentID)
}

func (de *DefaultExecutor) fSetInvisible() string {
	v := false
	de.visible = &v
	return ""
}

func (de *DefaultExecutor) fDeleteMessage(channelID, messageID string) string {

	err := de.bot.DeleteMessage(channelID, messageID)

	if err != nil {
		e := true
		de.error = &e
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fReadMessage(channelID, messageID string) string {

	text, err := de.bot.ReadMessage(channelID, messageID)

	if err != nil {
		e := true
		de.error = &e
		return err.Error()
	}
	return text
}
func (de *DefaultExecutor) fReadMessageV2(channelID, messageTS, threadTS string) string {

	text, err := de.bot.ReadMessageV2(channelID, messageTS, threadTS)

	if err != nil {
		e := true
		de.error = &e
		return err.Error()
	}
	return text
}

func (de *DefaultExecutor) fUpdateMessage(channelID, messageID, text string) string {

	err := de.bot.UpdateMessage(channelID, messageID, text)

	if err != nil {
		e := true
		de.error = &e
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fAddReactionToMessage(channelID, messageID, name string) string {

	err := de.bot.AddReaction(channelID, messageID, name)
	if err != nil {
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fRemoveReactionFromMessage(channelID, messageID, name string) string {

	err := de.bot.RemoveReaction(channelID, messageID, name)
	if err != nil {
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fAddRemoveReactionOnMessage(channelID, messageID, first, second string) string {

	err := de.bot.AddReaction(channelID, messageID, first)
	if err != nil {
		return err.Error()
	}
	err = de.bot.RemoveReaction(channelID, messageID, second)
	if err != nil {
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fAskOpenAI(params map[string]interface{}) string {
	apiKey, _ := params["apiKey"].(string)
	model, _ := params["model"].(string)
	timeout, _ := params["timeout"].(int)
	if timeout == 0 {
		timeout = 30
	}

	var messages []map[string]string
	if rawMessages, ok := params["messages"].([]interface{}); ok {
		for _, rawMsg := range rawMessages {
			if msg, ok := rawMsg.(map[string]interface{}); ok {
				role, roleOk := msg["role"].(string)
				content, contentOk := msg["content"].(string)
				if roleOk && contentOk {
					messages = append(messages, map[string]string{
						"role":    role,
						"content": content,
					})
				}
			}
		}
	}

	if len(messages) == 0 {
		messages = append(messages, map[string]string{
			"role":    "user",
			"content": "Hello",
		})
	}

	if apiKey == "" {
		e := true
		de.error = &e
		return "OpenAI API key is required"
	}

	options := vendors.OpenAIOptions{
		APIKey:   apiKey,
		Model:    model,
		Timeout:  timeout,
		Messages: messages,
	}

	openAI := vendors.NewOpenAI(options)
	response, err := openAI.CreateChatCompletion(options)
	log.Printf("OpenAI response: %s", string(response))
	if err != nil {
		e := true
		de.error = &e
		return fmt.Sprintf("OpenAI error: %s", err.Error())
	}

	return string(response)
}

func (de *DefaultExecutor) fAddDivider(channelID, ID string) string {
	err := de.bot.AddDivider(channelID, ID)

	if err != nil {
		e := true
		de.error = &e
		return err.Error()
	}
	return ""
}

func (de *DefaultExecutor) fSetError() string {
	e := true
	de.error = &e
	return ""
}

func (de *DefaultExecutor) render(obj interface{}) (string, []*common.Attachment, []common.Action, error) {

	gid := utils.GoRoutineID()

	var atts []*common.Attachment
	var acts []common.Action

	b, err := de.template.RenderObject(obj)
	if err != nil {
		de.attachments.Delete(gid) // cleanup attachments
		de.actions.Delete(gid)     // cleanup actions
		de.posts.Delete(gid)       // cleanup posts
		return "", atts, acts, err
	}

	at, ok := de.attachments.LoadAndDelete(gid)
	if ok {
		atts = at.([]*common.Attachment)
	}

	ac, ok := de.actions.LoadAndDelete(gid)
	if ok {
		dcas := ac.([]*DefaultCommandAction)
		for _, ca := range dcas {
			acts = append(acts, ca)
		}
	}

	return strings.TrimSpace(string(b)), atts, acts, nil
}

func (de *DefaultExecutor) execute(id string, obj interface{}, message common.Message) (string, []*common.Attachment, []common.Action, error) {

	t1 := time.Now()

	command := de.command
	processor := command.processor
	logger := command.logger

	labels := make(map[string]string)
	if !utils.IsEmpty(processor.name) {
		labels["group"] = processor.name
	}
	labels["command"] = command.name
	labels["bot"] = de.bot.Name()

	user := de.message.User()
	if !utils.IsEmpty(user) {
		labels["user_id"] = user.ID()
	}

	prefixes := []string{"default", "processor"}

	requests := processor.meter.Counter("processor", "requests", "Count of all executions", labels, prefixes...)
	requests.Inc()

	errors := processor.meter.Counter("processor", "errors", "Count of all errors during executions", labels, prefixes...)
	timeCounter := processor.meter.Counter("processor", "time", "Sum of all time executions", labels, prefixes...)

	name := command.getNameWithGroup("/")

	ids := ""
	var params interface{}

	if obj != nil {
		m, ok := obj.(map[string]interface{})
		if ok {
			ids = id
			params = m["params"]
			if !utils.IsEmpty(ids) {
				ids = fmt.Sprintf("id=%s ", ids)
			}

			// set real message which appears after first execution
			m["message"] = message
			if !utils.IsEmpty(message) {
				m["channel"] = message.Channel()
				m["user"] = message.User()
				m["caller"] = message.Caller()
			}
		}
	}

	logger.Debug("Default is executing command %s %swith params %v...", name, ids, params)

	text, atts, acts, err := de.render(obj)
	if err != nil {
		errors.Inc()
		return "", nil, nil, err
	}

	elapsed := time.Since(t1).Milliseconds()
	timeCounter.Add(int(elapsed))

	logger.Debug("Default is executed command %s %swith params %v in %s", name, ids, params, time.Since(t1))

	return text, atts, acts, nil
}

func (de *DefaultExecutor) defaultAfter(post *DefaultPost, parent common.Message, skipParent bool) error {

	var text string
	var atts []*common.Attachment

	executor, err := NewExecutor(post.Name, post.Path, de.command, de.bot, parent, de.params, nil)
	if err != nil {
		return err
	}

	text, atts, acts, err := executor.execute("", post.Obj, parent)
	if err != nil {
		return err
	}

	var channel common.Channel
	var user common.User

	if !utils.IsEmpty(parent) {
		channel = parent.Channel()
		user = parent.User()
	}
	if utils.IsEmpty(channel) {
		return nil
	}

	if utils.IsEmpty(text) {
		return nil
	}

	m := parent
	if skipParent {
		m = nil
	}

	_, err = de.bot.PostMessage(channel.ID(), text, atts, acts, user, m, de.Response())
	if err != nil {
		return err
	}
	return nil
}

func (de *DefaultExecutor) runbookAfterCallback(ret *DefaultRunbookStepResult, parent common.Message) error {

	if ret == nil {
		return nil
	}

	var channel common.Channel
	var user common.User

	if !utils.IsEmpty(parent) {
		channel = parent.Channel()
		user = parent.User()
	}
	if utils.IsEmpty(channel) {
		return nil
	}

	if ret.Error != nil {
		return ret.Error
	}

	if utils.IsEmpty(ret.Text) {
		return nil
	}

	m := parent

	_, err := de.bot.PostMessage(channel.ID(), ret.Text, ret.Attachements, ret.Actions, user, m, de.Response())
	if err != nil {
		return err
	}
	return nil
}

func (de *DefaultExecutor) runbookAfter(post *DefaultPost, message common.Message, waitGroup bool) error {

	rb, err := NewRunbook(post.Name, post.Path, de.command, de)
	if err != nil {
		return err
	}

	err = rb.Execute(de.bot, message, post.Obj, de.runbookAfterCallback, waitGroup)
	if err != nil {
		return err
	}
	return nil
}

func (de *DefaultExecutor) after(posts []*DefaultPost, message common.Message, skipParent bool, waitGroup bool) error {

	gr := &errgroup.Group{}
	var err error
	for _, p := range posts {

		gr.Go(func() error {

			var err error
			logger := de.command.logger

			switch p.Kind {
			case DefaultPostKindTemplate, DefaultPostKindCommand:

				err = de.defaultAfter(p, message, skipParent)
			case DefaultPostKindRunbook:

				err = de.runbookAfter(p, message, waitGroup)
			}

			if err != nil {
				logger.Error(err)
				return err
			}
			return nil
		})
	}
	if waitGroup {
		err = gr.Wait()
	}
	return err
}

func (de *DefaultExecutor) After(message common.Message) error {

	gid := utils.GoRoutineID()
	var posts []*DefaultPost

	r, ok := de.posts.Load(gid)
	if ok {
		posts = r.([]*DefaultPost)
	}

	err := de.after(posts, message, false, false)

	de.posts.Range(func(key, value any) bool {
		de.posts.Delete(key)
		return true
	})
	return err
}

func NewExecutorTemplate(name string, content string, executor *DefaultExecutor, observability *common.Observability) (*toolsRender.TextTemplate, error) {

	funcs := make(map[string]any)

	funcs["addFile"] = executor.fAddFile
	funcs["addAttachment"] = executor.fAddAttachment
	funcs["createAttachment"] = executor.fCreateAttachment

	funcs["addAction"] = executor.fAddAction
	funcs["addActionToMessage"] = executor.fAddActionToMessage
	funcs["addActionsToMessage"] = executor.fAddActionsToMessage
	funcs["removeActionFromMessage"] = executor.fRemoveActionFromMessage
	funcs["clearActionsFromMessage"] = executor.fClearActionsFromMessage

	funcs["addReaction"] = executor.fAddReactionToMessage
	funcs["addReactionToMessage"] = executor.fAddReactionToMessage
	funcs["addRemoveReactionOnMessage"] = executor.fAddRemoveReactionOnMessage
	funcs["removeReactionFromMessage"] = executor.fRemoveReactionFromMessage

	funcs["runFile"] = executor.fRunFile
	funcs["runCommand"] = executor.fRunCommand
	funcs["runTemplate"] = executor.fRunTemplate
	funcs["runBook"] = executor.fRunBook
	funcs["postFile"] = executor.fPostFile
	funcs["postCommand"] = executor.fPostCommand
	funcs["postTemplate"] = executor.fPostTemplate
	funcs["postBook"] = executor.fPostBook
	funcs["sendMessage"] = executor.fSendMessage
	funcs["sendMessageByParent"] = executor.fSendMessageByParent
	funcs["sendMessageEx"] = executor.fSendMessageEx
	funcs["setInvisible"] = executor.fSetInvisible
	funcs["setError"] = executor.fSetError
	funcs["deleteMessage"] = executor.fDeleteMessage
	funcs["readMessage"] = executor.fReadMessage
	funcs["readMessageV2"] = executor.fReadMessageV2

	funcs["updateMessage"] = executor.fUpdateMessage
	funcs["askOpenAI"] = executor.fAskOpenAI
	funcs["addDivider"] = executor.fAddDivider

	templateOpts := toolsRender.TemplateOptions{
		Name:    fmt.Sprintf("default-internal-%s", name),
		Content: string(content),
		Funcs:   funcs,
	}
	template, err := toolsRender.NewTextTemplate(templateOpts, observability)
	if err != nil {
		return nil, err
	}
	return template, nil
}

func NewExecutor(name, path string, command *DefaultCommand, bot common.Bot, message common.Message,
	params common.ExecuteParams, action common.Action) (*DefaultExecutor, error) {

	if !utils.FileExists(path) {
		return nil, fmt.Errorf("Default couldn't find template %s", path)
	}

	content, err := utils.Content(path)
	if err != nil {
		return nil, fmt.Errorf("Default couldn't read template %s, error: %s", path, err)
	}

	var visible *bool
	if command.config != nil {
		visible = command.config.Response.Visible
	}

	executor := &DefaultExecutor{
		command:     command,
		attachments: &sync.Map{},
		actions:     &sync.Map{},
		posts:       &sync.Map{},
		bot:         bot,
		message:     message,
		params:      params,
		action:      action,
		visible:     visible,
		error:       nil,
	}

	template, err := NewExecutorTemplate(name, string(content), executor, command.processor.observability)
	if err != nil {
		return nil, err
	}
	executor.template = template
	return executor, nil
}

// DefaultFieldWrapper

func (df *DefaultFieldWrapper) Name() string {
	return df.DefaultField.Name
}

func (df *DefaultFieldWrapper) Type() common.FieldType {
	return df.DefaultField.Type
}

func (df *DefaultFieldWrapper) Label() string {
	return df.DefaultField.Label
}

func (df *DefaultFieldWrapper) Values() []string {
	return df.DefaultField.Values
}

func (df *DefaultFieldWrapper) Default() string {
	return df.DefaultField.Default
}

func (df *DefaultFieldWrapper) Required() bool {
	return df.DefaultField.Required
}

func (df *DefaultFieldWrapper) Template() string {
	return df.DefaultField.Template
}

func (df *DefaultFieldWrapper) Dependencies() []string {
	return df.DefaultField.Dependencies
}

func (df *DefaultFieldWrapper) Hint() string {
	return df.DefaultField.Hint
}

func (df *DefaultFieldWrapper) Filter() string {
	return df.DefaultField.Filter
}

func (df *DefaultFieldWrapper) Value() string {
	return df.DefaultField.Value
}

func (df *DefaultFieldWrapper) Visible() bool {

	v := df.DefaultField.Visible
	if v == nil {
		return true
	}
	return *df.DefaultField.Visible
}

func (df *DefaultFieldWrapper) Parent() common.Field {
	return df.parent
}

func (df *DefaultFieldWrapper) Merge(f common.Field, empty bool) bool {
	if f == nil || df.DefaultField == nil {
		return false
	}
	field, ok := f.(*DefaultFieldWrapper)
	if !ok {
		return false
	}
	return df.DefaultField.merge(field.DefaultField, empty)
}

// DefaultField

func (df *DefaultField) merge(field *DefaultField, empty bool) bool {

	if field == nil {
		return false
	}

	ft := fmt.Sprintf("%s", field.Type)
	if !utils.IsEmpty(ft) || (utils.IsEmpty(ft) && empty) {
		df.Type = field.Type
	}
	if !utils.IsEmpty(field.Label) || (utils.IsEmpty(field.Label) && empty) {
		df.Label = field.Label
	}
	if !utils.IsEmpty(field.Default) || (utils.IsEmpty(field.Default) && empty) {
		df.Default = field.Default
	}
	if !utils.IsEmpty(field.Hint) || (utils.IsEmpty(field.Hint) && empty) {
		df.Hint = field.Hint
	}
	if field.Required && !df.Required {
		df.Required = field.Required
	}
	if len(field.Values) != 0 || (len(field.Values) == 0 && empty) {
		df.Values = field.Values
	}
	if len(field.Dependencies) != 0 || (len(field.Dependencies) == 0 && empty) {
		df.Dependencies = field.Dependencies
	}
	if !utils.IsEmpty(field.Filter) || (utils.IsEmpty(field.Filter) && empty) {
		df.Filter = field.Filter
	}
	if !utils.IsEmpty(field.Template) || (utils.IsEmpty(field.Template) && empty) {
		df.Template = field.Template
	}
	if !utils.IsEmpty(field.Value) || (utils.IsEmpty(field.Value) && empty) {
		df.Value = field.Value
	}
	return true
}

// DefaultFieldExecutor

func (de *DefaultFieldExecutor) fReadMessage(channelID, messageID string) string {

	text, err := de.bot.ReadMessage(channelID, messageID)
	if err != nil {
		return err.Error()
	}
	return text
}
func (de *DefaultFieldExecutor) fReadMessageV2(channelID, messageTS, threadTS string) string {

	text, err := de.bot.ReadMessageV2(channelID, messageTS, threadTS)

	if err != nil {

		return err.Error()
	}
	return text
}

func (de *DefaultFieldExecutor) fRunTemplate(fileName string, obj interface{}) (string, error) {

	s := fmt.Sprintf("%s%s%s", de.command.processor.options.TemplatesDir, string(os.PathSeparator), fileName)
	if !utils.FileExists(s) {
		return "", fmt.Errorf("Default couldn't find template file %s", s)
	}

	content, err := utils.Content(s)
	if err != nil {
		return "", fmt.Errorf("Default couldn't read template file %s, error: %s", s, err)
	}

	tOpts := toolsRender.TemplateOptions{
		Name:    fmt.Sprintf("default-internal-field-%s", de.field.Name),
		Content: string(content),
		Funcs:   de.funcs,
	}
	t, err := toolsRender.NewTextTemplate(tOpts, de.command.processor.observability)
	if err != nil {
		return "", err
	}
	return t.TemplateRenderFile(s, obj)
}

func (de *DefaultFieldExecutor) fFieldList(items ...*DefaultField) []*DefaultField {
	return items
}

func (de *DefaultFieldExecutor) fSetFieldLabel(label string) (string, error) {

	if de.field == nil || de.field.DefaultField == nil {
		return "", fmt.Errorf("Default couldn't set field label, field is nil")
	}
	de.field.DefaultField.Label = label
	return "", nil
}

func (de *DefaultFieldExecutor) fSetFieldValue(value string) (string, error) {

	if de.field == nil || de.field.DefaultField == nil {
		return "", fmt.Errorf("Default couldn't set field value, field is nil")
	}
	de.field.DefaultField.Value = value
	return "", nil
}

func (de *DefaultFieldExecutor) fSetFieldValues(values []string) (string, error) {

	if de.field == nil || de.field.DefaultField == nil {
		return "", fmt.Errorf("Default couldn't set field values, field is nil")
	}
	de.field.DefaultField.Values = values
	return "", nil
}

func (de *DefaultFieldExecutor) fAddField(name, typ, label string) *DefaultField {

	gid := utils.GoRoutineID()
	var fields []*DefaultField

	r, ok := de.fields.Load(gid)
	if ok {
		fields = r.([]*DefaultField)
	}

	field := &DefaultField{
		Name:  name,
		Type:  common.FieldType(typ),
		Label: label,
	}
	fields = append(fields, field)
	de.fields.Store(gid, fields)
	return field
}

func (de *DefaultFieldExecutor) fSetField(field *DefaultField, params map[string]interface{}) string {

	if field == nil || params == nil {
		return ""
	}

	name, ok := params["name"].(string)
	if ok {
		field.Name = name
	}

	typ, ok := params["type"].(string)
	if ok {
		field.Type = common.FieldType(typ)
	}

	label, ok := params["label"].(string)
	if ok {
		field.Label = label
	}

	values, ok := params["values"].([]string)
	if ok {
		field.Values = values
	}

	def, ok := params["default"].(string)
	if ok {
		field.Default = def
	}

	required, ok := params["required"].(bool)
	if ok {
		field.Required = required
	}

	template, ok := params["template"].(string)
	if ok {
		field.Template = template
	}

	deps, ok := params["dependencies"].([]string)
	if ok {
		field.Dependencies = deps
	}

	hint, ok := params["hint"].(string)
	if ok {
		field.Hint = hint
	}

	filter, ok := params["filter"].(string)
	if ok {
		field.Filter = filter
	}

	value := params["value"]
	if utils.IsEmpty(value) {
		field.Value = ""
	} else {
		field.Value = fmt.Sprintf("%v", value)
	}

	visible, ok := params["visible"].(bool)
	if ok {
		field.Visible = &visible
	}

	return ""
}

func (de *DefaultFieldExecutor) Execute() ([]*DefaultFieldWrapper, error) {

	m := make(map[string]interface{})
	m["bot"] = de.bot
	m["message"] = de.message
	m["channel"] = de.message.Channel()
	m["user"] = de.message.User()
	m["caller"] = de.message.Caller()
	m["params"] = de.params
	m["field"] = de.field

	b, err := de.template.RenderObject(m)
	if err != nil {
		return nil, err
	}

	var fnew *DefaultField
	fields := []*DefaultFieldWrapper{}

	if !utils.IsEmpty(string(b)) {

		// possible it's a field
		fnew = &DefaultField{}
		err = json.Unmarshal(b, fnew)
		if err != nil {
			return nil, err
		}
	}

	if !utils.IsEmpty(de.field) {
		de.field.merge(fnew, false)
	}

	gid := utils.GoRoutineID()

	var flds []*DefaultField
	r, ok := de.fields.Load(gid)
	if ok {
		flds = r.([]*DefaultField)
	}

	for _, f := range flds {
		if f == nil {
			continue
		}
		if utils.IsEmpty(f.Name) {
			continue
		}
		if fnew != nil && f.Name == fnew.Name {
			continue
		}
		fields = append(fields, &DefaultFieldWrapper{
			DefaultField: f,
			parent:       de.field,
		})
	}

	de.fields.Range(func(key, value any) bool {
		de.fields.Delete(key)
		return true
	})

	return fields, nil
}

func NewFieldExecutorTemplate(name string, content string, executor *DefaultFieldExecutor, observability *common.Observability) (*toolsRender.TextTemplate, map[string]any, error) {

	funcs := make(map[string]any)
	funcs["runTemplate"] = executor.fRunTemplate
	funcs["readMessage"] = executor.fReadMessage
	funcs["readMessageV2"] = executor.fReadMessageV2

	funcs["fieldList"] = executor.fFieldList
	funcs["setFieldLabel"] = executor.fSetFieldLabel
	funcs["setFieldValue"] = executor.fSetFieldValue
	funcs["setFieldValues"] = executor.fSetFieldValues
	funcs["setField"] = executor.fSetField
	funcs["addField"] = executor.fAddField

	funcs["setError"] = func() string { return "" }
	funcs["setInvisible"] = func() string { return "" }

	templateOpts := toolsRender.TemplateOptions{
		Name:    fmt.Sprintf("default-internal-%s", name),
		Content: string(content),
		Funcs:   funcs,
	}
	template, err := toolsRender.NewTextTemplate(templateOpts, observability)
	if err != nil {
		return nil, nil, err
	}
	return template, funcs, nil
}

func NewFieldExecutor(name, path string, command *DefaultCommand, bot common.Bot, message common.Message, params common.ExecuteParams, field *DefaultFieldWrapper) (*DefaultFieldExecutor, error) {

	if !utils.FileExists(path) {
		return nil, fmt.Errorf("Default couldn't find template %s", path)
	}

	content, err := utils.Content(path)
	if err != nil {
		return nil, fmt.Errorf("Default couldn't read template %s, error: %s", path, err)
	}

	executor := &DefaultFieldExecutor{
		command: command,
		fields:  &sync.Map{},
		bot:     bot,
		message: message,
		params:  params,
		field:   field,
	}

	template, funcs, err := NewFieldExecutorTemplate(name, string(content), executor, command.processor.observability)
	if err != nil {
		return nil, err
	}
	executor.template = template
	executor.funcs = funcs
	return executor, nil
}

// Default Runbook Command Executor

func (dre *DefaultRunbookCommandExecutor) execute() error {

	var response common.Response
	if !utils.IsEmpty(dre.runbookExecutor.runbook.parentExecutor) {
		response = dre.runbookExecutor.runbook.parentExecutor.Response()
	}

	var channel common.Channel
	var user common.User

	if !utils.IsEmpty(dre.message) {
		channel = dre.message.Channel()
		user = dre.message.User()
	}
	if utils.IsEmpty(channel) {
		return nil
	}

	m := dre.message

	return dre.bot.Command(channel.ID(), dre.command, user, m, response)
}

// Default Runbook Executor

func (dre *DefaultRunbookExecutor) execute(id string, params map[string]interface{}, message common.Message) *DefaultRunbookStepResult {

	if dre.templateExecutor != nil {
		r := &DefaultRunbookStepResult{
			ID: fmt.Sprintf("%s.template", id),
		}
		r.Text, r.Attachements, r.Actions, r.Error = dre.templateExecutor.execute(id, params, message)
		return r
	} else if dre.commandExecutor != nil {
		r := &DefaultRunbookStepResult{
			ID: fmt.Sprintf("%s.command", id),
		}
		r.Error = dre.commandExecutor.execute()
		return r
	}
	return nil
}

func (dre *DefaultRunbookExecutor) loadPosts() []*DefaultPost {

	gid := utils.GoRoutineID()
	var posts []*DefaultPost

	if dre.templateExecutor != nil {
		r, ok := dre.templateExecutor.posts.LoadAndDelete(gid)
		if ok {
			posts = r.([]*DefaultPost)
		}
	}
	return posts
}

func NewRunbookExecutor(rb *DefaultRunbook, step *DefaultRunbookStep, bot common.Bot, message common.Message, params common.ExecuteParams) (*DefaultRunbookExecutor, error) {

	if utils.IsEmpty(step.Template) && utils.IsEmpty(step.Command) {
		return nil, nil
	}

	observability := rb.command.processor.observability

	rExecutor := &DefaultRunbookExecutor{
		runbook:     rb,
		step:        step,
		description: common.Render(step.Step, params, observability),
	}

	if !utils.IsEmpty(step.Template) {

		tExecutor := &DefaultRunbookTemplateExecutor{
			command:     rb.command,
			attachments: &sync.Map{},
			actions:     &sync.Map{},
			posts:       &sync.Map{},
			bot:         bot,
			message:     message,
			params:      params,
		}

		name := fmt.Sprintf("runbook-%s", rb.name)
		template, err := NewExecutorTemplate(name, step.Template, tExecutor, observability)
		if err != nil {
			return nil, err
		}
		tExecutor.template = template
		rExecutor.templateExecutor = tExecutor
	}

	if !utils.IsEmpty(step.Command) {

		cExecutor := &DefaultRunbookCommandExecutor{
			runbookExecutor: rExecutor,
			bot:             bot,
			message:         message,
			params:          params,
			command:         common.Render(step.Command, params, observability),
		}
		rExecutor.commandExecutor = cExecutor
	}
	return rExecutor, nil
}

// Default Runbook

func (dr *DefaultRunbook) countPipelineSteps(pl []*DefaultRunbookStep) int {

	r := 0
	for _, v := range pl {
		if !v.Disabled {
			r++
		}
	}
	return r
}

func (dr *DefaultRunbook) runPipeline(id string, pl []*DefaultRunbookStep, bot common.Bot, parent common.Message, params map[string]interface{},
	callback DefaultRunbookStepResultFunc, waitGroup bool) error {

	if dr.countPipelineSteps(pl) == 0 {
		return nil
	}

	g := &errgroup.Group{}

	for i, step := range pl {

		id1 := strconv.Itoa(i)
		if !utils.IsEmpty(step.ID) {
			id1 = step.ID
		}
		if !utils.IsEmpty(id) {
			id1 = fmt.Sprintf("%s.%s", id, id1)
		}
		if step.Disabled {
			continue
		}

		g.Go(func() error {

			executor, err := NewRunbookExecutor(dr, step, bot, parent, params)
			if err != nil {
				return err
			}
			if executor == nil {
				return nil
			}

			r1 := executor.execute(id1, params, parent)
			if r1 != nil && r1.Error != nil {
				return r1.Error
			}
			if r1 == nil {
				return nil
			}

			r1.ID = id1
			err = callback(r1, parent)
			if err != nil {
				return err
			}

			posts := executor.loadPosts()
			if len(posts) > 0 {
				err = dr.parentExecutor.after(posts, parent, false, false)
				if err != nil {
					return err
				}
			}

			err = dr.runPipeline(id1, step.Pipeline, bot, parent, params, callback, true)
			if err != nil {
				return err
			}
			return nil
		})
	}
	if waitGroup {
		return g.Wait()
	}
	return nil
}

func (dr *DefaultRunbook) Execute(bot common.Bot, message common.Message, obj interface{}, callback DefaultRunbookStepResultFunc, waitGroup bool) error {

	if dr.countPipelineSteps(dr.config.Pipeline) == 0 {
		dr.command.logger.Debug("Default runbook %s has no pipepline steps. Skipped", dr.name)
	}

	dr.command.logger.Debug("Default is processing runbook %s...", dr.name)

	params := make(common.ExecuteParams)
	ps, ok := obj.(map[string]interface{})
	if ok {
		params = ps
	}
	return dr.runPipeline("", dr.config.Pipeline, bot, message, params, callback, waitGroup)
}

func NewRunbook(name, path string, command *DefaultCommand, parentExecutor *DefaultExecutor) (*DefaultRunbook, error) {

	if !utils.FileExists(path) {
		return nil, fmt.Errorf("Default couldn't find runbook %s", path)
	}

	bytes, err := utils.Content(path)
	if err != nil {
		return nil, err
	}

	var config DefaultRunbookConfig
	err = yaml.Unmarshal(bytes, &config)
	if err != nil {
		return nil, err
	}

	rb := &DefaultRunbook{
		name:           name,
		path:           path,
		command:        command,
		config:         &config,
		parentExecutor: parentExecutor,
	}
	return rb, nil
}

// DefaultCommandResponse

func (dcr *DefaultCommandResponse) Visible() bool {
	if dcr.command.config != nil {
		v := dcr.command.config.Response.Visible
		if v != nil {
			return *v
		}
	}
	return false
}

func (dcr *DefaultCommandResponse) Duration() bool {
	if dcr.command.config != nil {
		d := dcr.command.config.Response.Duration
		if d != nil {
			return *d
		}
	}
	return false
}

func (dcr *DefaultCommandResponse) Original() bool {
	if dcr.command.config != nil {
		o := dcr.command.config.Response.Original
		if o != nil {
			return *o
		}
	}
	return false
}

func (dcr *DefaultCommandResponse) Error() bool {
	return false
}

// DefaultCommandApproval

func (dca *DefaultCommandApproval) approval() *DefaultApproval {
	if dca.command.config == nil {
		return nil
	}
	approval := dca.command.config.Approval
	if approval == nil || approval.Disabled {
		return nil
	}
	return dca.command.config.Approval
}

func (dca *DefaultCommandApproval) Description() bool {

	a := dca.approval()
	if a == nil {
		return false
	}
	return a.Description
}

func (dca *DefaultCommandApproval) Visible() bool {

	a := dca.approval()
	if a == nil {
		return false
	}
	return a.Visible
}

func (dca *DefaultCommandApproval) Reasons() []string {

	a := dca.approval()
	if a == nil {
		return []string{}
	}
	return a.Reasons
}

func (dca *DefaultCommandApproval) Channel(bot common.Bot, message common.Message, params common.ExecuteParams) string {

	a := dca.approval()
	if a == nil {
		return ""
	}
	if utils.IsEmpty(a.Channel) {
		return ""
	}

	content := ""
	name := fmt.Sprintf("%s-approval-channel", dca.command.name)
	path := fmt.Sprintf("%s%s%s", dca.command.processor.options.TemplatesDir, string(os.PathSeparator), a.Channel)

	if utils.FileExists(path) {
		data, err := utils.Content(path)
		if err != nil {
			dca.command.logger.Error("Default approval channel %s command %s error: %s", path, dca.command.name, err)
			return ""
		}
		content = string(data)
	} else {
		content = a.Channel
	}

	funcs := make(map[string]any)
	dca.addTemplateFunctions(funcs, bot, message, params)

	tOpts := toolsRender.TemplateOptions{
		Name:    fmt.Sprintf("default-internal-%s", name),
		Content: string(content),
		Funcs:   funcs,
	}

	t, err := toolsRender.NewTextTemplate(tOpts, dca.command.processor.observability)
	if err != nil {
		dca.command.logger.Error("Default approval channel %s command %s create error: %s", path, dca.command.name, err)
		return ""
	}

	m := make(map[string]interface{})
	m["bot"] = bot
	m["message"] = message
	m["channel"] = message.Channel()
	m["user"] = message.User()
	m["caller"] = message.Caller()
	m["params"] = params

	b, err := t.RenderObject(m)
	if err != nil {
		dca.command.logger.Error("Default approval channel %s command %s render error: %s", path, dca.command.name, err)
		return err.Error()
	}
	return string(b)
}

func (dca *DefaultCommandApproval) Message(bot common.Bot, message common.Message, params common.ExecuteParams) string {

	a := dca.approval()
	if a == nil {
		return ""
	}
	if utils.IsEmpty(a.Template) {
		return ""
	}

	content := ""
	name := fmt.Sprintf("%s-approval-message", dca.command.name)
	path := fmt.Sprintf("%s%s%s", dca.command.processor.options.TemplatesDir, string(os.PathSeparator), a.Template)

	if utils.FileExists(path) {
		data, err := utils.Content(path)
		if err != nil {
			dca.command.logger.Error("Default approval template %s command %s error: %s", path, dca.command.name, err)
			return ""
		}
		content = string(data)
	} else {
		content = a.Template
	}

	funcs := make(map[string]any)
	dca.addTemplateFunctions(funcs, bot, message, params)

	tOpts := toolsRender.TemplateOptions{
		Name:    fmt.Sprintf("default-internal-%s", name),
		Content: string(content),
		Funcs:   funcs,
	}

	t, err := toolsRender.NewTextTemplate(tOpts, dca.command.processor.observability)
	if err != nil {
		dca.command.logger.Error("Default approval template %s command %s create error: %s", path, dca.command.name, err)
		return ""
	}

	m := make(map[string]interface{})
	m["bot"] = bot
	m["message"] = message
	m["channel"] = message.Channel()
	m["user"] = message.User()
	m["caller"] = message.Caller()
	m["params"] = params

	b, err := t.RenderObject(m)
	if err != nil {
		dca.command.logger.Error("Default approval template %s command %s render error: %s", path, dca.command.name, err)
		return err.Error()
	}
	return string(b)
}

// DefaultCommandAction

func (dca *DefaultCommandAction) Name() string {
	return dca.name
}

func (dca *DefaultCommandAction) Label() string {
	return dca.label
}

func (dca *DefaultCommandAction) Template() string {
	return dca.template
}

func (dca *DefaultCommandAction) Style() string {
	return dca.style
}

// Default command

func (dc *DefaultCommand) Name() string {
	return dc.name
}

func (dc *DefaultCommand) Group() string {
	if dc.processor == nil {
		return dc.processor.name
	}
	return ""
}

func (dc *DefaultCommand) getNameWithGroup(delim string) string {

	name := dc.name
	if !utils.IsEmpty(dc.processor.name) {
		name = fmt.Sprintf("%s%s%s", dc.processor.name, delim, dc.name)
	}
	return name
}

func (dc *DefaultCommand) Description() string {
	if dc.config == nil {
		return ""
	}
	return dc.config.Description
}

func (dc *DefaultCommand) Params() []string {

	params := []string{}
	if dc.config != nil {
		params = dc.config.Params
	}
	if utils.IsEmpty(params) {
		s := ""
		r := []string{}
		for i := 0; i < 10; i++ {
			n := fmt.Sprintf("p%d", i)
			if s == "" {
				s = fmt.Sprintf("(?P<%s>\\S+)", n)
			} else {
				s = fmt.Sprintf("%s\\s+(?P<%s>\\S+)", s, n)
			}
			r = append(r, s)
		}
		return r
	}
	return params
}

func (dc *DefaultCommand) Aliases() []string {
	if dc.config == nil {
		return []string{}
	}
	return dc.config.Aliases
}

func (dc *DefaultCommand) Actions() []common.Action {

	r := []common.Action{}
	if dc.config == nil {
		return r
	}
	for _, a := range dc.config.Actions {
		r = append(r, &DefaultCommandAction{
			command:  dc,
			name:     a.Name,
			label:    a.Label,
			template: a.Template,
			style:    a.Style,
		})
	}
	return r
}

func (dc *DefaultCommand) configFieldsAsCommonFields(fields []*DefaultField) []*DefaultFieldWrapper {

	r := []*DefaultFieldWrapper{}
	for _, field := range fields {
		if field == nil {
			continue
		}
		var nf DefaultField
		err := copier.CopyWithOption(&nf, field, copier.Option{IgnoreEmpty: true, DeepCopy: true})
		if err != nil {
			dc.logger.Error("Default command %s field %s copy error: %s", dc.name, field.Name, err)
			continue
		}
		r = append(r, &DefaultFieldWrapper{
			DefaultField: &nf,
		})
	}
	return r
}

func (dc *DefaultCommand) flatFields(items []*DefaultFieldWrapper, fields *sync.Map) []common.Field {

	r := []common.Field{}
	for _, item := range items {

		if item == nil {
			continue
		}

		new := item

		name := item.Name()
		fl, ok := fields.Load(name)
		if ok {
			new = fl.(*DefaultFieldWrapper)
		}

		if utils.IsEmpty(new) {
			continue
		}

		r = append(r, new)

		children := new.children
		if len(children) > 0 {
			rc := dc.flatFields(children, fields)
			r = append(r, rc...)
		}
	}
	return r
}

func (dc *DefaultCommand) Fields(bot common.Bot, message common.Message, params common.ExecuteParams, eval []string, parent common.Field) []common.Field {

	if dc.config == nil {
		return []common.Field{}
	}

	list := eval

	items := dc.configFieldsAsCommonFields(dc.config.Fields)

	if !utils.IsEmpty(parent) {
		pName := parent.Name()
		if !utils.Contains(list, pName) {
			list = append(list, pName)
		}
		p := parent.(*DefaultFieldWrapper)
		if p != nil && p.children != nil {
			items = append(items, p.children...)
		}
	}

	fields := &sync.Map{}

	if utils.IsEmpty(message) {
		return dc.flatFields(items, fields)
	}

	wGroup := &sync.WaitGroup{}

	for _, field := range items {

		fName := field.Name()
		if !utils.Contains(list, fName) {
			continue
		}

		fTemplate := field.Template()
		if utils.IsEmpty(fTemplate) {
			continue
		}

		skip := utils.IsEmpty(dc.processor.options.TemplatesDir)
		if skip {
			continue
		}

		wGroup.Add(1)
		go func(fw *DefaultFieldWrapper) {

			defer wGroup.Done()

			name := fmt.Sprintf("%s-%s", dc.name, fw.DefaultField.Name)
			path := fmt.Sprintf("%s%s%s", dc.processor.options.TemplatesDir, string(os.PathSeparator), fw.DefaultField.Template)

			executor, err := NewFieldExecutor(name, path, dc, bot, message, params, fw)
			if err != nil {
				dc.logger.Error("Default field template %s command %s field %s executor error: %s", path, dc.name, fw.DefaultField.Name, err)
				return
			}

			flds, err := executor.Execute()
			if err != nil {
				dc.logger.Error("Default field template %s command %s field %s create error: %s", path, dc.name, fw.DefaultField.Name, err)
				return
			}

			fw.children = flds
			fields.Store(fw.DefaultField.Name, fw)
		}(field)
	}
	wGroup.Wait()

	r := dc.flatFields(items, fields)

	return r
}

func (dc *DefaultCommand) Priority() int {
	if dc.config != nil {
		return dc.config.Priority
	}
	return 0
}

func (dc *DefaultCommand) Wrapper() bool {
	if dc.config != nil {
		return dc.config.Wrapper
	}
	return false
}

func (dc *DefaultCommand) Schedule() string {
	if dc.config != nil {
		return dc.config.Schedule
	}
	return ""
}

func (dc *DefaultCommand) Channel() string {
	if dc.config != nil {
		return dc.config.Channel
	}
	return ""
}

func (dc *DefaultCommand) Confirmation(params common.ExecuteParams) string {

	if dc.config != nil {

		content := dc.config.Confirmation
		name := fmt.Sprintf("%s-confirmation", dc.name)

		tOpts := toolsRender.TemplateOptions{
			Name:    fmt.Sprintf("default-internal-%s", name),
			Content: string(content),
		}

		t, err := toolsRender.NewTextTemplate(tOpts, dc.processor.observability)
		if err != nil {
			dc.logger.Error("Default command %s create error: %s", dc.name, err)
			return ""
		}

		b, err := t.RenderObject(params)
		if err != nil {
			dc.logger.Error("Default command %s render error: %s", dc.name, err)
			return ""
		}
		return string(b)

	}
	return ""
}

func (dc *DefaultCommand) Approval() common.Approval {

	if dc.config != nil && dc.config.Approval != nil {
		return &DefaultCommandApproval{
			command: dc,
		}
	}
	return nil
}

func (dc *DefaultCommand) Permissions() bool {

	if dc.config != nil && dc.config.Permissions != nil {
		return *dc.config.Permissions
	}
	return true
}

func (dc *DefaultCommand) Response() common.Response {

	return &DefaultCommandResponse{
		command: dc,
	}
}

func (dc *DefaultCommand) Execute(bot common.Bot, message common.Message, params common.ExecuteParams, action common.Action) (common.Executor, string, []*common.Attachment, []common.Action, error) {

	name := dc.getNameWithGroup("-")

	path := dc.path
	if action != nil && !utils.IsEmpty(action.Template()) {
		path = fmt.Sprintf("%s%s%s", dc.processor.options.TemplatesDir, string(os.PathSeparator), action.Template())
	}

	executor, err := NewExecutor(name, path, dc, bot, message, params, action)
	if err != nil {
		return nil, "", nil, nil, err
	}

	m := make(map[string]interface{})
	m["params"] = params
	m["bot"] = bot
	m["message"] = message
	m["user"] = message.User()
	m["caller"] = message.Caller()
	m["channel"] = message.Channel()
	m["name"] = dc.getNameWithGroup("/")

	if action != nil {
		m["action"] = action
	}

	msg, atts, acts, err := executor.execute("", m, message)
	if err != nil {
		dc.logger.Error(err)
		err = fmt.Errorf("%s", dc.processor.options.Error)
		return nil, "", nil, nil, err
	}
	return executor, msg, atts, acts, err
}

// Default

func (d *Default) Name() string {
	return d.name
}

func (d *Default) Commands() []common.Command {
	return d.commands
}

func (d *Default) loadConfig(path string) (*DefaultCommandConfig, error) {

	if !utils.FileExists(path) {
		return nil, nil
	}

	bytes, err := utils.Content(path)
	if err != nil {
		return nil, err
	}

	var v DefaultCommandConfig
	err = yaml.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (d *Default) createCommand(name, path string) (*DefaultCommand, error) {

	logger := d.observability.Logs()

	var err error
	var config *DefaultCommandConfig
	if !utils.IsEmpty(d.options.ConfigExt) {

		dFile := filepath.Dir(path)
		pConfig := filepath.Join(dFile, fmt.Sprintf("%s%s", name, d.options.ConfigExt))
		config, err = d.loadConfig(pConfig)
		if err != nil {
			logger.Error("Default couldn't read config %s, error: %s", path, err)
		}
	}

	dc := &DefaultCommand{
		name:      name,
		path:      path,
		config:    config,
		processor: d,
		logger:    logger,
	}

	_, err = NewExecutorTemplate(name, path, &DefaultExecutor{}, dc.processor.observability)
	if err != nil {
		return nil, fmt.Errorf("Default file %s error: %s", path, err)
	}

	return dc, nil
}

func (d *Default) AddCommand(name, path string) error {

	logger := d.observability.Logs()

	dc, err := d.createCommand(name, path)
	if err != nil {
		logger.Error(err)
		return err
	}
	d.commands = append(d.commands, dc)
	return nil
}

func NewDefault(name string, options DefaultOptions, observability *common.Observability, processors *common.Processors) *Default {

	return &Default{
		name:          name,
		options:       options,
		processors:    processors,
		meter:         observability.Metrics(),
		observability: observability,
	}
}

func (dca *DefaultCommandApproval) addTemplateFunctions(funcs map[string]any, bot common.Bot, message common.Message, params common.ExecuteParams) {
	funcs["getBot"] = func() interface{} { return bot }
	funcs["getUser"] = func() interface{} { return message.User() }
	funcs["getParams"] = func() interface{} { return params }
	funcs["getMessage"] = func() interface{} { return message }
	funcs["getChannel"] = func() interface{} { return message.Channel() }

	funcs["runTemplate"] = func(fileName string, obj interface{}) (string, error) {
		path := fmt.Sprintf("%s%s%s", dca.command.processor.options.TemplatesDir, string(os.PathSeparator), fileName)
		if !utils.FileExists(path) {
			return "", fmt.Errorf("couldn't find template file %s", path)
		}

		content, err := utils.Content(path)
		if err != nil {
			return "", fmt.Errorf("error reading template %s: %v", path, err)
		}

		templateName := fmt.Sprintf("approval-runtemplate-%s", fileName)
		templateOpts := toolsRender.TemplateOptions{
			Name:    templateName,
			Content: string(content),
		}

		t, err := toolsRender.NewTextTemplate(templateOpts, dca.command.processor.observability)
		if err != nil {
			return "", fmt.Errorf("error creating template %s: %v", fileName, err)
		}

		result, err := t.RenderObject(obj)
		if err != nil {
			return "", fmt.Errorf("error rendering template %s: %v", fileName, err)
		}

		return string(result), nil
	}

	// postTemplate cannot be used in the approval template (as it implements after)

	funcs["isEmpty"] = utils.IsEmpty
}
