package processor

import (
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
	"gopkg.in/yaml.v2"
)

type DefaultOptions struct {
	CommandsDir  string
	TemplatesDir string
	CommandExt   string
	ConfigExt    string
	Description  string
	Error        string
}

type DefaultConfig struct {
	Description string
	Params      []string
	Aliases     []string
	Response    common.Response
	Fields      []common.Field
}

type DefaultCommand struct {
	name        string
	config      *DefaultConfig
	processor   *Default
	template    *toolsRender.TextTemplate
	attachments *sync.Map
	posts       *sync.Map
}

type DefaultPost struct {
	File string
	Obj  interface{}
}

type Default struct {
	name          string
	options       DefaultOptions
	processors    *common.Processors
	commands      []common.Command
	meter         sreCommon.Meter
	observability *common.Observability
}

// Default command

func (dc *DefaultCommand) Name() string {
	return dc.name
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

func (dc *DefaultCommand) Response() common.Response {
	if dc.config != nil {
		return dc.config.Response
	}
	return common.Response{}
}

func (dc *DefaultCommand) Fields() []common.Field {
	if dc.config != nil {
		return dc.config.Fields
	}
	return []common.Field{}
}

func (dc *DefaultCommand) Execute(bot common.Bot, user common.User, params common.ExecuteParams) (string, []*common.Attachment, error) {

	t1 := time.Now()

	labels := make(map[string]string)
	if !utils.IsEmpty(dc.processor.name) {
		labels["group"] = dc.processor.name
	}
	labels["command"] = dc.name
	labels["bot"] = bot.Name()
	labels["user_id"] = user.ID()

	prefixes := []string{"default", "processor"}

	requests := dc.processor.meter.Counter("requests", "Count of all executions", labels, prefixes...)
	requests.Inc()

	errors := dc.processor.meter.Counter("errors", "Count of all errors during executions", labels, prefixes...)
	timeCounter := dc.processor.meter.Counter("time", "Sum of all time executions", labels, prefixes...)

	gid := utils.GoRoutineID()
	logger := dc.processor.observability.Logs()

	m := make(map[string]interface{})
	m["params"] = params
	m["bot"] = bot
	m["user"] = user

	name := dc.name
	if !utils.IsEmpty(dc.processor.name) {
		name = fmt.Sprintf("%s/%s", dc.processor.name, dc.name)
	}
	m["name"] = name

	logger.Debug("Default is executing command %s with params %v...", name, params)

	var atts []*common.Attachment

	b, err := dc.template.RenderObject(m)
	if err != nil {
		dc.attachments.Delete(gid) // cleanup attachments
		dc.posts.Delete(gid)       // cleanup posts
		errors.Inc()
		logger.Error(err)
		return "", atts, fmt.Errorf("%s", dc.processor.options.Error)
	}

	r, ok := dc.attachments.LoadAndDelete(gid)
	if ok {
		atts = r.([]*common.Attachment)
	}

	elapsed := time.Since(t1).Milliseconds()
	timeCounter.Add(int(elapsed))

	return strings.TrimSpace(string(b)), atts, nil
}

func (dc *DefaultCommand) After(bot common.Bot, user common.User, params common.ExecuteParams,
	message common.Message, channel common.Channel) error {

	gid := utils.GoRoutineID()
	var posts []*DefaultPost

	r, ok := dc.posts.LoadAndDelete(gid)
	if ok {
		posts = r.([]*DefaultPost)
	}

	for _, p := range posts {
		go func(post *DefaultPost) {

			logger := dc.processor.observability.Logs()

			dNew, err := dc.processor.CreateCommand(dc.name, post.File)
			if err != nil {
				logger.Error(err)
				return
			}

			text, atts, err := dNew.Execute(bot, user, params)
			if err != nil {
				logger.Error(err)
				return
			}

			err = bot.Post(channel, text, atts, message)
			if err != nil {
				logger.Error(err)
				return
			}

		}(p)
	}
	return nil
}

func (dc *DefaultCommand) fileFullName(dir, file string) string {
	return fmt.Sprintf("%s%s%s", dir, string(os.PathSeparator), file)
}

func (dc *DefaultCommand) fPostTemplate(file string, obj interface{}) error {

	gid := utils.GoRoutineID()
	var posts []*DefaultPost

	r, ok := dc.posts.Load(gid)
	if ok {
		posts = r.([]*DefaultPost)
	}

	posts = append(posts, &DefaultPost{
		File: dc.fileFullName(dc.processor.options.TemplatesDir, file),
		Obj:  obj,
	})
	dc.posts.Store(gid, posts)
	return nil
}

func (dc *DefaultCommand) fAddAttachment(title, text string, data interface{}, typ string) error {

	gid := utils.GoRoutineID()
	var atts []*common.Attachment

	r, ok := dc.attachments.Load(gid)
	if ok {
		atts = r.([]*common.Attachment)
	}

	dBytes, ok := data.([]byte)
	if !ok {
		s := fmt.Sprintf("%v", data)
		dBytes = []byte(s)
	}

	atts = append(atts, &common.Attachment{
		Title: title,
		Text:  text,
		Data:  dBytes,
		Type:  common.AttachmentType(typ),
	})
	dc.attachments.Store(gid, atts)
	return nil
}

func (dc *DefaultCommand) fRunCommand(file string, obj interface{}) (string, error) {

	return dc.template.TemplateRenderFile(dc.fileFullName(dc.processor.options.CommandsDir, file), obj)
}

func (dc *DefaultCommand) fRunTemplate(file string, obj interface{}) (string, error) {

	return dc.template.TemplateRenderFile(dc.fileFullName(dc.processor.options.TemplatesDir, file), obj)
}

// Default

func (d *Default) Name() string {
	return d.name
}

func (d *Default) Commands() []common.Command {
	return d.commands
}

func (d *Default) loadConfig(path string) (*DefaultConfig, error) {

	if !utils.FileExists(path) {
		return nil, nil
	}

	bytes, err := utils.Content(path)
	if err != nil {
		return nil, err
	}

	var v DefaultConfig
	err = yaml.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (d *Default) CreateCommand(name, path string) (common.Command, error) {

	logger := d.observability.Logs()

	content, err := utils.Content(path)
	if err != nil {
		logger.Error("Default couldn't read template %s, error %s", path, err)
		return nil, err
	}

	var config *DefaultConfig
	if !utils.IsEmpty(d.options.ConfigExt) {

		dFile := filepath.Dir(path)
		pConfig := filepath.Join(dFile, fmt.Sprintf("%s%s", name, d.options.ConfigExt))
		config, err = d.loadConfig(pConfig)
		if err != nil {
			logger.Error("Default couldn't read config %s, error %s", path, err)
		}
	}

	dc := &DefaultCommand{
		attachments: &sync.Map{},
		posts:       &sync.Map{},
		config:      config,
	}

	funcs := make(map[string]any)
	funcs["addAttachment"] = dc.fAddAttachment
	funcs["runCommand"] = dc.fRunCommand
	funcs["runTemplate"] = dc.fRunTemplate
	funcs["postTemplate"] = dc.fPostTemplate

	templateOpts := toolsRender.TemplateOptions{
		Name:    fmt.Sprintf("default_%s_template", name),
		Content: string(content),
		Funcs:   funcs,
	}
	template, err := toolsRender.NewTextTemplate(templateOpts, d.observability)
	if err != nil {
		logger.Error("Default template %s in file %s has error: %s", name, path, err)
		return nil, err
	}

	dc.name = name
	dc.processor = d
	dc.template = template
	return dc, nil
}

func (d *Default) AddCommand(name, path string) error {

	dc, err := d.CreateCommand(name, path)
	if err != nil {
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
