package processor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
	"golang.org/x/sync/errgroup"

	"gopkg.in/yaml.v2"
)

type DefaultRunbookStepResult struct {
	ID           string
	Text         string
	Attachements []*common.Attachment
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
	posts       *sync.Map
	bot         common.Bot
	params      common.ExecuteParams
	message     common.Message
	template    *toolsRender.TextTemplate
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

type DefaultReposne struct {
	Visible  bool
	Original bool
	Duration bool
}

type DefaultApproval struct {
	Channel  string
	Template string
}

type DefaultCommandConfig struct {
	Description  string
	Params       []string
	Aliases      []string
	Response     DefaultReposne
	Fields       []common.Field
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

func (de *DefaultExecutor) Error() bool {
	if de.error != nil {
		return *de.error
	}
	return false
}

func (de *DefaultExecutor) Visible() bool {
	if de.visible != nil {
		return *de.visible
	}
	if de.command.config != nil {
		return de.command.config.Response.Visible
	}
	return false
}

func (de *DefaultExecutor) Duration() bool {
	if de.command.config != nil {
		return de.command.config.Response.Duration
	}
	return false
}

func (de *DefaultExecutor) Original() bool {
	if de.command.config != nil {
		return de.command.config.Response.Original
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

func (de *DefaultExecutor) fSendMessageEx(message, channels string, params map[string]interface{}) (string, error) {

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

	var user common.User
	if !utils.IsEmpty(de.message) {
		user = de.message.User()
	}

	var err error
	for _, ch := range chnls {
		e := de.bot.Post(ch, message, atts, user, nil, de.Response())
		if e != nil {
			de.command.logger.Error(e)
			err = e
		}
	}

	return "", err
}

func (de *DefaultExecutor) fSendMessage(message, channels string) (string, error) {
	return de.fSendMessageEx(message, channels, nil)
}

func (de *DefaultExecutor) fSetInvisible() string {
	v := false
	de.visible = &v
	return ""
}

func (de *DefaultExecutor) fDeleteMessage(channelID, messageTimestamp string) string {

	err := de.bot.Delete(channelID, messageTimestamp)

	if err != nil {
		e := true
		de.error = &e
		errorMessage := err.Error()

		return errorMessage
	}
	return ""
}

func (de *DefaultExecutor) fAddReaction(channelID, messageTimestamp, name string) string {

	de.bot.AddReaction(channelID, messageTimestamp, name)

	return ""
}

func (de *DefaultExecutor) fSetError() string {
	e := true
	de.error = &e
	return ""
}

func (de *DefaultExecutor) fGetBot() interface{} {
	return de.bot
}

func (de *DefaultExecutor) fGetUser() interface{} {
	if utils.IsEmpty(de.message) {
		return nil
	}
	return de.message.User()
}

func (de *DefaultExecutor) fGetParams() interface{} {
	return de.params
}

func (de *DefaultExecutor) fGetMessage() interface{} {
	return de.message
}

func (de *DefaultExecutor) fGetChannel() interface{} {
	if utils.IsEmpty(de.message) {
		return nil
	}
	return de.message.Channel()
}

func (de *DefaultExecutor) render(obj interface{}) (string, []*common.Attachment, error) {

	gid := utils.GoRoutineID()

	var atts []*common.Attachment

	b, err := de.template.RenderObject(obj)
	if err != nil {
		de.attachments.Delete(gid) // cleanup attachments
		de.posts.Delete(gid)       // cleanup posts
		return "", atts, err
	}

	r, ok := de.attachments.LoadAndDelete(gid)
	if ok {
		atts = r.([]*common.Attachment)
	}

	return strings.TrimSpace(string(b)), atts, nil
}

func (de *DefaultExecutor) execute(id string, obj interface{}) (string, []*common.Attachment, error) {

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

	requests := processor.meter.Counter("requests", "Count of all executions", labels, prefixes...)
	requests.Inc()

	errors := processor.meter.Counter("errors", "Count of all errors during executions", labels, prefixes...)
	timeCounter := processor.meter.Counter("time", "Sum of all time executions", labels, prefixes...)

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
		}
	}

	logger.Debug("Default is executing command %s %swith params %v...", name, ids, params)

	text, atts, err := de.render(obj)
	if err != nil {
		errors.Inc()
		return "", nil, err
	}

	elapsed := time.Since(t1).Milliseconds()
	timeCounter.Add(int(elapsed))

	logger.Debug("Default is executed command %s %swith params %v in %s", name, ids, params, time.Since(t1))

	return text, atts, nil
}

func (de *DefaultExecutor) defaultAfter(post *DefaultPost, parent common.Message, skipParent bool) error {

	var text string
	var atts []*common.Attachment

	executor, err := NewExecutor(post.Name, post.Path, de.command, de.bot, parent, de.params)
	if err != nil {
		return err
	}

	text, atts, err = executor.execute("", post.Obj)
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

	err = de.bot.Post(channel.ID(), text, atts, user, m, de.Response())
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

	err := de.bot.Post(channel.ID(), ret.Text, ret.Attachements, user, m, de.Response())
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
	funcs["runFile"] = executor.fRunFile
	funcs["runCommand"] = executor.fRunCommand
	funcs["runTemplate"] = executor.fRunTemplate
	funcs["runBook"] = executor.fRunBook
	funcs["postFile"] = executor.fPostFile
	funcs["postCommand"] = executor.fPostCommand
	funcs["postTemplate"] = executor.fPostTemplate
	funcs["postBook"] = executor.fPostBook
	funcs["sendMessage"] = executor.fSendMessage
	funcs["sendMessageEx"] = executor.fSendMessageEx
	funcs["setInvisible"] = executor.fSetInvisible
	funcs["setError"] = executor.fSetError
	funcs["deleteMessage"] = executor.fDeleteMessage
	funcs["addReaction"] = executor.fAddReaction
	funcs["getBot"] = executor.fGetBot
	funcs["getUser"] = executor.fGetUser
	funcs["getParams"] = executor.fGetParams
	funcs["getMessage"] = executor.fGetMessage
	funcs["getChannel"] = executor.fGetChannel

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

func NewExecutor(name, path string, command *DefaultCommand, bot common.Bot, message common.Message, params common.ExecuteParams) (*DefaultExecutor, error) {

	if !utils.FileExists(path) {
		return nil, fmt.Errorf("Default couldn't find template %s", path)
	}

	content, err := utils.Content(path)
	if err != nil {
		return nil, fmt.Errorf("Default couldn't read template %s, error: %s", path, err)
	}

	executor := &DefaultExecutor{
		command:     command,
		attachments: &sync.Map{},
		posts:       &sync.Map{},
		bot:         bot,
		message:     message,
		params:      params,
	}

	template, err := NewExecutorTemplate(name, string(content), executor, command.processor.observability)
	if err != nil {
		return nil, err
	}
	executor.template = template
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

func (dre *DefaultRunbookExecutor) execute(id string, params map[string]interface{}) *DefaultRunbookStepResult {

	if dre.templateExecutor != nil {
		r := &DefaultRunbookStepResult{
			ID: fmt.Sprintf("%s.template", id),
		}
		r.Text, r.Attachements, r.Error = dre.templateExecutor.execute(id, params)
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

			r1 := executor.execute(id1, params)
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
		return dcr.command.config.Response.Visible
	}
	return false
}

func (dcr *DefaultCommandResponse) Duration() bool {
	if dcr.command.config != nil {
		return dcr.command.config.Response.Duration
	}
	return false
}

func (dcr *DefaultCommandResponse) Original() bool {
	if dcr.command.config != nil {
		return dcr.command.config.Response.Original
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
	return dca.command.config.Approval
}

func (dca *DefaultCommandApproval) Channel() string {

	a := dca.approval()
	if a == nil {
		return ""
	}
	return a.Channel
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
	name := fmt.Sprintf("%s-approval", dca.command.name)
	path := fmt.Sprintf("%s%s%s", dca.command.processor.options.TemplatesDir, string(os.PathSeparator), a.Template)

	if utils.FileExists(path) {
		data, err := utils.Content(path)
		if err != nil {
			dca.command.logger.Error("Default template %s command %s error: %s", path, dca.command.name, err)
			return ""
		}
		content = string(data)
	} else {
		content = a.Template
	}

	tOpts := toolsRender.TemplateOptions{
		Name:    fmt.Sprintf("default-internal-%s", name),
		Content: string(content),
	}

	t, err := toolsRender.NewTextTemplate(tOpts, dca.command.processor.observability)
	if err != nil {
		dca.command.logger.Error("Default template %s command %s create error: %s", path, dca.command.name, err)
		return ""
	}

	m := make(map[string]interface{})
	m["bot"] = bot
	m["message"] = message
	m["channel"] = message.Channel()
	m["user"] = message.User()
	m["params"] = params

	b, err := t.RenderObject(m)
	if err != nil {
		dca.command.logger.Error("Default template %s command %s render error: %s", path, dca.command.name, err)
		return ""
	}
	return string(b)
}

// Default command

func (dc *DefaultCommand) Name() string {
	return dc.name
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

func (dc *DefaultCommand) Fields(bot common.Bot, message common.Message, only []string) []common.Field {

	if dc.config == nil {
		return []common.Field{}
	}

	if utils.IsEmpty(message) {
		return dc.config.Fields
	}

	fields := &sync.Map{}
	wGroup := &sync.WaitGroup{}

	for _, field := range dc.config.Fields {

		if utils.IsEmpty(field.Template) {
			continue
		}

		skip := utils.IsEmpty(dc.processor.options.TemplatesDir)
		if !skip && len(only) > 0 {
			skip = !utils.Contains(only, field.Name)
		}

		if skip {
			continue
		}

		content := ""
		name := fmt.Sprintf("%s-%s", dc.name, field.Name)

		path := fmt.Sprintf("%s%s%s", dc.processor.options.TemplatesDir, string(os.PathSeparator), field.Template)
		if utils.FileExists(path) {
			data, err := utils.Content(path)
			if err != nil {
				dc.logger.Error("Default template %s command %s field %s error: %s", path, dc.name, field.Name, err)
				continue
			}
			content = string(data)
		} else {
			content = field.Template
		}

		wGroup.Add(1)
		go func(wg *sync.WaitGroup, name, content string, f common.Field, fs *sync.Map) {
			defer wGroup.Done()

			tOpts := toolsRender.TemplateOptions{
				Name:    fmt.Sprintf("default-internal-%s", name),
				Content: string(content),
			}

			t, err := toolsRender.NewTextTemplate(tOpts, dc.processor.observability)
			if err != nil {
				dc.logger.Error("Default template %s command %s field %s create error: %s", path, dc.name, f.Name, err)
				return
			}

			m := make(map[string]interface{})
			m["bot"] = bot
			m["message"] = message
			m["channel"] = message.Channel()
			m["user"] = message.User()
			m["field"] = f

			b, err := t.RenderObject(m)
			if err != nil {
				dc.logger.Error("Default template %s command %s field %s render error: %s", path, dc.name, f.Name, err)
				return
			}

			var fnew = common.Field{}
			err = json.Unmarshal(b, &fnew)
			if err != nil {
				dc.logger.Error("Default template %s command %s unmarshall field %s error: %s", path, dc.name, f.Name, err)
				return
			}
			fields.Store(f.Name, fnew)

		}(wGroup, name, content, field, fields)
	}
	wGroup.Wait()

	newFields := []common.Field{}
	for _, field := range dc.config.Fields {

		newField := common.Field{
			Name:     field.Name,
			Type:     field.Type,
			Label:    field.Label,
			Default:  field.Default,
			Hint:     field.Hint,
			Required: field.Required,
			Values:   field.Values,
			Template: field.Template,
		}
		r, ok := fields.Load(field.Name)
		if ok {
			f, ok := r.(common.Field)
			if !ok {
				continue
			}
			if f.Type != "" {
				newField.Type = f.Type
			}
			if !utils.IsEmpty(f.Label) {
				newField.Label = f.Label
			}
			if !utils.IsEmpty(f.Default) {
				newField.Default = f.Default
			}
			if !utils.IsEmpty(f.Hint) {
				newField.Hint = f.Hint
			}
			if f.Required && !newField.Required {
				newField.Required = f.Required
			}
			if len(f.Values) != 0 {
				newField.Values = f.Values
			}
		}
		newFields = append(newFields, newField)
	}

	return newFields
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

func (dc *DefaultCommand) Confirmation() string {
	if dc.config != nil {
		return dc.config.Confirmation
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

func (dc *DefaultCommand) Execute(bot common.Bot, message common.Message, params common.ExecuteParams) (common.Executor, string, []*common.Attachment, error) {

	name := dc.getNameWithGroup("-")

	executor, err := NewExecutor(name, dc.path, dc, bot, message, params)
	if err != nil {
		return nil, "", nil, err
	}

	m := make(map[string]interface{})
	m["params"] = params
	m["bot"] = bot
	m["message"] = message
	m["user"] = message.User()
	m["channel"] = message.Channel()
	m["name"] = dc.getNameWithGroup("/")

	msg, atts, err := executor.execute("", m)
	if err != nil {
		dc.logger.Error(err)
		err = fmt.Errorf("%s", dc.processor.options.Error)
		return nil, "", nil, err
	}
	return executor, msg, atts, err
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
