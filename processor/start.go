package processor

import (
	"strings"
	"text/template"

	"github.com/devopsext/chatops/common"
)

type StartOptions struct {
	Template string
}

type Start struct {
	template *template.Template
	options  StartOptions
}

func (s *Start) Name() string {
	return "start"
}

func (s *Start) Contains(command string) common.Executor {
	if strings.ToLower(command) == s.Name() {
		return s
	}
	return nil
}

func (s *Start) Execute(command string, payload, args interface{}, callback common.ExecuteCallback) (bool, error) {

	if s.template == nil {
		return false, nil
	}

	var b strings.Builder
	err := s.template.Execute(&b, nil)
	if err != nil {
		return false, err
	}

	return false, nil
}

func NewStart(options StartOptions, observability common.Observability) *Start {

	logger := observability.Logs()

	t, err := common.LoadTemplate(options.Template)
	if err != nil {
		logger.Error(err)
	}

	if t == nil {
		logger.Debug("Start has no template.")
	}

	return &Start{
		options:  options,
		template: t,
	}
}
