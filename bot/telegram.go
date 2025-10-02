package bot

import (
	"sync"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
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
	processors *common.Processors
	bot        *tgbotapi.BotAPI
	logger     sreCommon.Logger
	//metricer sre.MetricsCounter
}

func (t *Telegram) Name() string {
	return "Telegram"
}

func (t *Telegram) sendTyping(m *tgbotapi.Message) {

	t.bot.Send(tgbotapi.NewChatAction(m.Chat.ID, tgbotapi.ChatTyping))
}

func (t *Telegram) sendMessage(m *tgbotapi.Message, text string) {

	if !utils.IsEmpty(text) {
		response := tgbotapi.NewMessage(m.Chat.ID, text)
		t.bot.Send(response)
	}
}

/*
func (t *Telegram) processMessage(m *tgbotapi.Message) {

		command := m.Command()
		executor := t.processors.Executor(command)
		if executor == nil {
			t.logger.Debug("Command %s is not found", command)
			return
		}

		t.sendTyping(m)

		_, err := executor.Execute(t, command, "", m.CommandArguments(), func(text string) bool {

			t.sendMessage(m, text)
			return true
		})

		if err != nil {
			t.logger.Error(err)
		}
	}
*/
func (t *Telegram) start() {

	bot, err := tgbotapi.NewBotAPI(t.options.BotToken)
	if err != nil {
		t.logger.Error(err)
		return
	}
	bot.Debug = t.options.Debug
	t.bot = bot

	u := tgbotapi.NewUpdate(t.options.Offset)
	u.Timeout = t.options.Timeout

	var wg sync.WaitGroup

	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		t.logger.Error(err)
		return
	}

	for update := range updates {
		if update.Message != nil && update.Message.IsCommand() {
			t.logger.Debug("Message: [%s] %s", update.Message.From.UserName, update.Message.Text)

			m := tgbotapi.Message{}
			copier.Copy(&m, update.Message)

			wg.Add(1)
			go func(m *tgbotapi.Message) {
				defer wg.Done()
				//t.processMessage(update.Message)
			}(&m)
		}
		if update.CallbackQuery != nil && update.CallbackQuery.Message != nil {
			t.logger.Debug("Callback: [%s] %s", update.CallbackQuery.Message.From.UserName, update.CallbackQuery.Message.Text)
		}
	}
}

func (t *Telegram) Start(wg *sync.WaitGroup) {

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

// Stop gracefully shuts down the Telegram bot
func (t *Telegram) Stop() {
	t.logger.Info("Stopping Telegram bot...")
	// Add any cleanup code here if needed in the future
}

func NewTelegram(options TelegramOptions, observability *common.Observability, processors *common.Processors) *Telegram {

	return &Telegram{
		options:    options,
		processors: processors,
		logger:     observability.Logs(),
		//metrics: observability.Metrics().Counter(),
	}
}
