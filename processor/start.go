package processor

import (
	"strings"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
)

type StartTemplate struct {
	Name string
}

type StartOptions struct {
	Template    string
	Description string
}

type Start struct {
	template   *toolsRender.TextTemplate
	processors *common.Processors
	options    StartOptions
	logger     sreCommon.Logger
}

type StartResponse struct {
	start  *Start
	params common.ExecuteParams
	bot    common.Bot
}

const (
	startName        = "start"
	startDescription = "List of all commands across the service"
)

func (sr *StartResponse) Message() (string, error) {

	m := make(map[string]interface{})
	m["processors"] = sr.start.processors
	m["params"] = sr.params
	m["bot"] = sr.bot.Name()

	b, err := sr.start.template.RenderObject(m)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (sr *StartResponse) Attachments() []*common.ResponseAttachement {
	return []*common.ResponseAttachement{}
}

func (s *Start) Name() string {
	return startName
}

func (s *Start) Description() string {

	desc := s.options.Description
	if utils.IsEmpty(desc) {
		desc = startDescription
	}
	return desc
}

func (s *Start) Commands() []common.Command {
	return nil
}

func (s *Start) Params() []string {
	return []string{}
}

func (s *Start) Execute(bot common.Bot, params common.ExecuteParams) (common.Response, error) {

	sr := &StartResponse{
		start:  s,
		params: params,
		bot:    bot,
	}
	return sr, nil
}

func NewStart(options StartOptions, observability *common.Observability, processors *common.Processors) *Start {

	logger := observability.Logs()

	templateOpts := toolsRender.TemplateOptions{
		Content: options.Template,
	}
	template, err := toolsRender.NewTextTemplate(templateOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	return &Start{
		options:    options,
		template:   template,
		processors: processors,
		logger:     logger,
	}
}
