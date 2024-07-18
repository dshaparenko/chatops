package processor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
	"github.com/jinzhu/copier"
	"gopkg.in/yaml.v2"
)

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

type DefaultCommandConfig struct {
	Description string
	Params      []string
	Aliases     []string
	Response    DefaultReposne
	Fields      []common.Field
	Priority    int
	Wrapper     bool
	Schedule    string
}

type DefaultCommand struct {
	name      string
	path      string
	config    *DefaultCommandConfig
	processor *Default
	logger    sreCommon.Logger
}

type DefaultPost struct {
	Name string
	Path string
	Obj  interface{}
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

type Default struct {
	name          string
	options       DefaultOptions
	processors    *common.Processors
	commands      []common.Command
	meter         sreCommon.Meter
	observability *common.Observability
}

type DefaultRunbookConfig struct {
}

type DefaultRunbook struct {
	name      string
	path      string
	config    *DefaultRunbookConfig
	processor *Default
	logger    sreCommon.Logger
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

func (de *DefaultExecutor) filePath(dir, fileName string) string {
	return fmt.Sprintf("%s%s%s", dir, string(os.PathSeparator), fileName)
}

func (de *DefaultExecutor) fPostFile(path string, obj interface{}) string {

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
	})
	de.posts.Store(gid, posts)
	return ""
}

func (de *DefaultExecutor) fPostCommand(fileName string, obj interface{}) string {
	s := de.filePath(de.command.processor.options.CommandsDir, fileName)
	return de.fPostFile(s, obj)
}

func (de *DefaultExecutor) fPostTemplate(fileName string, obj interface{}) string {
	s := de.filePath(de.command.processor.options.TemplatesDir, fileName)
	return de.fPostFile(s, obj)
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

	/*gid := utils.GoRoutineID()
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
	de.attachments.Store(gid, atts)*/
	return ""
}

func (de *DefaultExecutor) fRunFile(path string, obj interface{}) (string, error) {
	return de.template.TemplateRenderFile(path, obj)
}

func (de *DefaultExecutor) fRunCommand(fileName string, obj interface{}) (string, error) {
	s := de.filePath(de.command.processor.options.CommandsDir, fileName)
	return de.template.TemplateRenderFile(s, obj)
}

func (de *DefaultExecutor) fRunTemplate(fileName string, obj interface{}) (string, error) {
	s := de.filePath(de.command.processor.options.TemplatesDir, fileName)
	return de.template.TemplateRenderFile(s, obj)
}

func (de *DefaultExecutor) fRunBook(fileName string, obj interface{}) string {
	s := de.filePath(de.command.processor.options.RunbooksDir, fileName)
	return s
	//return de.template.TemplateRenderFile(s, obj)
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

	var err error
	for _, ch := range chnls {
		e := de.bot.Post(ch, message, atts, nil)
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

func (de *DefaultExecutor) execute(obj interface{}) (string, []*common.Attachment, error) {

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
	logger.Debug("Default is executing command %s with params %v...", name, de.params)

	text, atts, err := de.render(obj)
	if err != nil {
		errors.Inc()
		return "", nil, err
	}

	elapsed := time.Since(t1).Milliseconds()
	timeCounter.Add(int(elapsed))

	return text, atts, nil
}

func (de *DefaultExecutor) After(message common.Message) error {

	gid := utils.GoRoutineID()
	var posts []*DefaultPost

	r, ok := de.posts.LoadAndDelete(gid)
	if ok {
		posts = r.([]*DefaultPost)
	}

	for _, p := range posts {
		go func(post *DefaultPost) {

			command := de.command
			logger := command.logger

			executor, err := NewExecutor(post.Name, post.Path, command, de.bot, message, de.params)
			if err != nil {
				logger.Error(err)
				return
			}

			text, atts, err := executor.execute(post.Obj)
			if err != nil {
				logger.Error(err)
				return
			}

			if utils.IsEmpty(text) {
				return
			}

			channel := message.Channel()
			if utils.IsEmpty(channel) {
				return
			}

			err = de.bot.Post(channel.ID(), text, atts, message)
			if err != nil {
				logger.Error(err)
				return
			}

		}(p)
	}
	return nil
}

func NewExecutorTemplate(name string, path string, executor *DefaultExecutor, observability *common.Observability) (*toolsRender.TextTemplate, error) {

	content, err := utils.Content(path)
	if err != nil {
		return nil, fmt.Errorf("Default couldn't read template %s, error: %s", path, err)
	}

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
	funcs["sendMessage"] = executor.fSendMessage
	funcs["sendMessageEx"] = executor.fSendMessageEx
	funcs["setInvisible"] = executor.fSetInvisible
	funcs["setError"] = executor.fSetError
	funcs["deleteMessage"] = executor.fDeleteMessage
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

	executor := &DefaultExecutor{
		command:     command,
		attachments: &sync.Map{},
		posts:       &sync.Map{},
		bot:         bot,
		message:     message,
		params:      params,
	}

	template, err := NewExecutorTemplate(name, path, executor, command.processor.observability)
	if err != nil {
		return nil, err
	}
	executor.template = template
	return executor, nil
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

func (dc *DefaultCommand) Fields(bot common.Bot, message common.Message) []common.Field {

	if dc.config != nil {
		if utils.IsEmpty(message) {
			return dc.config.Fields
		}

		fields := &sync.Map{}
		wGroup := &sync.WaitGroup{}

		for _, field := range dc.config.Fields {

			fPath := fmt.Sprintf("%s%s%s", dc.processor.options.TemplatesDir, string(os.PathSeparator), field.Template)
			if utils.FileExists(fPath) {

				wGroup.Add(1)
				go func(wg *sync.WaitGroup, path string, f common.Field, fs *sync.Map) {
					defer wGroup.Done()

					name := fmt.Sprintf("%s-%s", dc.name, f.Name)
					content, err := utils.Content(path)
					if err != nil {
						dc.logger.Error("Default template %s command %s field %s error: %s", path, dc.name, f.Name, err)
						return
					}

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

				}(wGroup, fPath, field, fields)
			}
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
	return []common.Field{}
}

func (dc *DefaultCommand) ParamsSetDefaults(eParams map[string]interface{}, fields []common.Field) map[string]interface{} {
	newParams := make(map[string]interface{})
	copier.Copy(&newParams, eParams)
	for _, field := range fields {
		if !utils.IsEmpty(eParams[field.Name]) {
			newParams[field.Name] = eParams[field.Name]
		} else if !utils.IsEmpty(field.Default) {
			newParams[field.Name] = fmt.Sprintf("%v", field.Default)
		}
	}
	return newParams
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

func (dc *DefaultCommand) Execute(bot common.Bot, message common.Message, params common.ExecuteParams) (common.Executor, string, []*common.Attachment, error) {

	name := dc.getNameWithGroup("_")

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

	msg, atts, err := executor.execute(m)
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
