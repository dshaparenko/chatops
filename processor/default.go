package processor

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/devopsext/chatops/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v2"
)

type DefaultOptions struct {
	CommandsDir string
	CommandExt  string
	ConfigExt   string
	Description string
	Error       string
}

type DefaultConfig struct {
	Params []string
}

type DefaultCommand struct {
	name        string
	params      []string
	processor   *Default
	template    *toolsRender.TextTemplate
	attachments *sync.Map
}

type Default struct {
	name          string
	options       DefaultOptions
	processors    *common.Processors
	commands      []common.Command
	observability *common.Observability
}

// Default command

func (dc *DefaultCommand) Name() string {
	return dc.name
}

func (dc *DefaultCommand) Description() string {
	return ""
}

func (dc *DefaultCommand) Params() []string {

	if utils.IsEmpty(dc.params) {
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
	return dc.params
}

func (dc *DefaultCommand) Execute(bot common.Bot, user common.User, params common.ExecuteParams) (string, []*common.Attachment, error) {

	gid := utils.GoRoutineID()
	logger := dc.processor.observability.Logs()

	m := make(map[string]interface{})
	//m["processors"] = dc.processor.processors.Items()
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
		logger.Error(err)
		return "", atts, fmt.Errorf("%s", dc.processor.options.Error)
	}

	r, ok := dc.attachments.LoadAndDelete(gid)
	if ok {
		atts = r.([]*common.Attachment)
	}

	return strings.TrimSpace(string(b)), atts, nil
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

func (d *Default) AddCommand(name, path string) error {

	logger := d.observability.Logs()

	content, err := utils.Content(path)
	if err != nil {
		logger.Error("Default couldn't read template %s, error %s", path, err)
		return err
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
	}

	if config != nil {
		dc.params = config.Params
	}

	funcs := make(map[string]any)
	funcs["addAttachment"] = dc.fAddAttachment

	templateOpts := toolsRender.TemplateOptions{
		Name:    fmt.Sprintf("default_%s_template", name),
		Content: string(content),
		Funcs:   funcs,
	}
	template, err := toolsRender.NewTextTemplate(templateOpts, d.observability)
	if err != nil {
		logger.Error("Default template %s in file %s has error: %s", name, path, err)
		return err
	}

	dc.name = name
	dc.processor = d
	dc.template = template

	d.commands = append(d.commands, dc)
	return nil
}

func NewDefault(name string, options DefaultOptions, observability *common.Observability, processors *common.Processors) *Default {

	return &Default{
		name:          name,
		options:       options,
		processors:    processors,
		observability: observability,
	}
}
