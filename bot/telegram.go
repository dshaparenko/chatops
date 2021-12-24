package bot

import (
	"sync"

	"github.com/devopsext/chatops/common"
	sre "github.com/devopsext/sre/common"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/jinzhu/copier"
)

type TelegramOptions struct {
	BotToken string
	Debug    bool
	Timeout  int
	Offset   int
}

type Telegram struct {
	options    TelegramOptions
	processors common.Processors
	logger     sre.Logger
	tracer     sre.Tracer
	//metricer sre.MetricsCounter
}

func (t *Telegram) processMessage(m *tgbotapi.Message) {

	command := m.Command()
	executor := t.processors.Executor(command)
	if executor == nil {
		t.logger.Debug("Command %s is not found")
		return
	}
	executor.Execute(command, "", m.CommandArguments())
}

func (t *Telegram) Start() {

	bot, err := tgbotapi.NewBotAPI(t.options.BotToken)
	if err != nil {
		t.logger.Error(err)
		return
	}
	bot.Debug = t.options.Debug

	u := tgbotapi.NewUpdate(t.options.Offset)
	u.Timeout = t.options.Timeout

	var wg sync.WaitGroup

	updates := bot.GetUpdatesChan(u)
	for update := range updates {
		if update.Message != nil && update.Message.IsCommand() {
			t.logger.Debug("Message: [%s] %s", update.Message.From.UserName, update.Message.Text)

			m := tgbotapi.Message{}
			copier.Copy(&m, update.Message)

			wg.Add(1)
			go func(m *tgbotapi.Message) {
				defer wg.Done()
				t.processMessage(update.Message)
			}(&m)
		}
		if update.CallbackQuery != nil && update.CallbackQuery.Message != nil {
			t.logger.Debug("Callback: [%s] %s", update.CallbackQuery.Message.From.UserName, update.CallbackQuery.Message.Text)
		}
	}
}

func (t *Telegram) StartInWaitGroup(wg *sync.WaitGroup) {

	wg.Add(1)

	go func(wg *sync.WaitGroup) {

		defer wg.Done()
		t.Start()
	}(wg)
}

func NewTelegram(options TelegramOptions, observability common.Observability, processors common.Processors) *Telegram {
	return &Telegram{
		options:    options,
		processors: processors,
		logger:     observability.Logs(),
		tracer:     observability.Traces(),
		//metrics: observability.Metrics().Counter(),
	}
}
