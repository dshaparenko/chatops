package processor

import (
	"fmt"
	"strings"
	"sync"

	"github.com/devopsext/chatops/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
)

type DefaultOptions struct {
	Dir         string
	Pattern     string
	Description string
}

type DefaultCommand struct {
	name        string
	processor   *Default
	template    *toolsRender.TextTemplate
	attachments *sync.Map
}

type Default struct {
	name          string
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
	return []string{"p0", "p1", "p2", "p3", "p4", "p5"}
}

func (dc *DefaultCommand) Execute(bot common.Bot, user common.User, params common.ExecuteParams) (string, []*common.Attachment, error) {

	gid := utils.GoRoutineID()

	m := make(map[string]interface{})
	m["processors"] = dc.processor.processors.Items()
	m["params"] = params
	m["bot"] = bot.Name()
	m["user"] = user

	var atts []*common.Attachment

	b, err := dc.template.RenderObject(m)
	if err != nil {
		return "", atts, err
	}

	r, ok := dc.attachments.LoadAndDelete(gid)
	if ok {
		atts = r.([]*common.Attachment)
	}

	return strings.TrimSpace(string(b)), atts, nil
}

func (dc *DefaultCommand) fAddAttachment(title, text string, data interface{}) error {

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

func (d *Default) AddCommand(name, path string) error {

	logger := d.observability.Logs()

	content, err := utils.Content(path)
	if err != nil {
		logger.Error("Default couldn't read content of %s, error %s", path, err)
		return err
	}

	dc := &DefaultCommand{
		attachments: &sync.Map{},
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

func NewDefault(name string, observability *common.Observability, processors *common.Processors) *Default {

	return &Default{
		name:          name,
		processors:    processors,
		observability: observability,
	}
}
