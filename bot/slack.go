package bot

import (
	"context"
	"sync"

	"github.com/devopsext/chatops/common"
	sre "github.com/devopsext/sre/common"
	"github.com/shomali11/slacker"
)

type SlackOptions struct {
	BotToken string
	AppToken string
	Debug    bool
}

type Slack struct {
	options    SlackOptions
	processors common.Processors
	bot        *slacker.Slacker
	logger     sre.Logger
	tracer     sre.Tracer
}

func (s *Slack) Name() string {
	return "Slack"
}

func (s *Slack) Start() {

	bot := slacker.NewClient(s.options.BotToken, s.options.AppToken, slacker.WithDebug(s.options.Debug))

	for _, p := range s.processors.Items() {
		bot.Command(p.Name(), &slacker.CommandDefinition{
			Description: "Echo a word!",
			Example:     "echo hello",
			Handler: func(botCtx slacker.BotContext, request slacker.Request, response slacker.ResponseWriter) {
				//_ := request.Param("word")
				response.Reply("test")
			},
		})
	}
	s.bot = bot

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := bot.Listen(ctx)
	if err != nil {
		s.logger.Error(err)
		return
	}
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
		options:    options,
		processors: processors,
		logger:     observability.Logs(),
		tracer:     observability.Traces(),
	}
}
