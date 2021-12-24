package bot

import (
	"sync"

	"github.com/devopsext/chatops/common"
	sre "github.com/devopsext/sre/common"
)

type SlackOptions struct {
	BotToken string
	AppToken string
}

type Slack struct {
	options SlackOptions
	logger  sre.Logger
	tracer  sre.Tracer
}

func (s *Slack) Start() {
}

func (t *Slack) StartInWaitGroup(wg *sync.WaitGroup) {

	wg.Add(1)

	go func(wg *sync.WaitGroup) {

		defer wg.Done()
		t.Start()
	}(wg)
}

func NewSlack(options SlackOptions, observability common.Observability, processors common.Processors) *Slack {
	return &Slack{
		options: options,
		logger:  observability.Logs(),
		tracer:  observability.Traces(),
	}
}
