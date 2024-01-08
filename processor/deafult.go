package processor

import (
	"fmt"
	"strings"

	"github.com/devopsext/chatops/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
)

type DefaultOptions struct {
	Dir     string
	Pattern string
}

type DefaultResponse struct {
	dc     *DefaultCommand
	params common.ExecuteParams
	bot    common.Bot
}

type DefaultCommand struct {
	name      string
	processor *Default
	template  *toolsRender.TextTemplate
}

type Default struct {
	name          string
	processors    *common.Processors
	commands      []common.Command
	observability *common.Observability
}

// Default response

func (dr *DefaultResponse) Message() (string, error) {

	m := make(map[string]interface{})
	//m["processors"] = sr.buildProcessors()
	m["params"] = dr.params
	m["bot"] = dr.bot.Name()

	b, err := dr.dc.template.RenderObject(m)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (dr *DefaultResponse) Attachments() []*common.ResponseAttachement {
	return []*common.ResponseAttachement{}
}

// Default command

func (dc *DefaultCommand) Name() string {
	return dc.name
}

func (dc *DefaultCommand) Description() string {
	return ""
}

func (dc *DefaultCommand) Params() []string {
	return []string{}
}

func (dc *DefaultCommand) Execute(bot common.Bot, params common.ExecuteParams) (common.Response, error) {
	dr := &DefaultResponse{
		dc:     dc,
		params: params,
		bot:    bot,
	}
	return dr, nil
}

// Default

func (d *Default) Name() string {
	return d.name
}

func (d *Default) Commands() []common.Command {
	return d.commands
}

func (d *Default) AddCommand(name, path string) {

	logger := d.observability.Logs()

	content, err := utils.Content(path)
	if err != nil {
		logger.Error("Default; couldn't read content of %s, error %s", path, err)
		return
	}

	templateOpts := toolsRender.TemplateOptions{
		Name:    fmt.Sprintf("default_%s", name),
		Content: string(content),
	}
	template, err := toolsRender.NewTextTemplate(templateOpts, d.observability)
	if err != nil {
		logger.Error(err)
		return
	}

	dc := &DefaultCommand{
		name:      name,
		processor: d,
		template:  template,
	}
	d.commands = append(d.commands, dc)
}

func NewDefault(name string, observability *common.Observability, processors *common.Processors) *Default {

	return &Default{
		name:          name,
		processors:    processors,
		observability: observability,
	}
}
