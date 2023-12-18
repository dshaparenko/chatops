package processor

import (
	"strings"
	"text/template"

	"github.com/devopsext/chatops/common"
)

type StartTemplate struct {
	Name string
}

type StartOptions struct {
	Template string
}

type Start struct {
	template *template.Template
	options  StartOptions
}

const startName = "start"

func (s *Start) Name() string {
	return startName
}

func (s *Start) Contains(command string) common.Executor {
	if strings.ToLower(command) == s.Name() {
		return s
	}
	return nil
}

func (s *Start) Execute(bot common.Bot, command string, payload, args interface{}, send common.ExecutorSendFunc) (bool, error) {

	if s.template == nil {
		return false, nil
	}

	var b strings.Builder
	err := s.template.Execute(&b, &StartTemplate{
		Name: bot.Name(),
	})
	if err != nil {
		return false, err
	}

	if send != nil {
		return send(b.String()), nil
	}
	return false, nil
}

func NewStart(options StartOptions, observability *common.Observability) *Start {

	logger := observability.Logs()

	t, err := common.LoadTemplate(startName, options.Template)
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
