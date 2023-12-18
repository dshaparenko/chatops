package bot

import (
	"context"
	"sync"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/slack-io/slacker"
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
	logger     sreCommon.Logger
}

func (s *Slack) Name() string {
	return "Slack"
}

func (s *Slack) start() {

	bot := slacker.NewClient(s.options.BotToken, s.options.AppToken, slacker.WithDebug(s.options.Debug))

	/*for _, p := range s.processors.Items() {
		bot.Command(p.Name(), &slacker.CommandDefinition{
			Description: "Echo a word!",
			Example:     "echo hello",
			Handler: func(botCtx slacker.BotContext, request slacker.Request, response slacker.ResponseWriter) {
				//_ := request.Param("word")
				response.Reply("test")
			},
		})
	}*/
	s.bot = bot

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := bot.Listen(ctx)
	if err != nil {
		s.logger.Error(err)
		return
	}
}

func (t *Slack) Start(wg *sync.WaitGroup) {

	if wg == nil {
		t.start()
		return
	}

	wg.Add(1)

	go func(wg *sync.WaitGroup) {

		defer wg.Done()
		t.start()
	}(wg)
}

func NewSlack(options SlackOptions, observability *common.Observability, processors common.Processors) *Slack {

	return &Slack{
		options:    options,
		processors: processors,
		logger:     observability.Logs(),
	}
}
