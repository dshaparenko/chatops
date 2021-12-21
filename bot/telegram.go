package bot

import (
	"sync"

	"github.com/devopsext/chatops/common"
	sre "github.com/devopsext/sre/common"
)

type TelegramOptions struct {
	BotToken string
	Debug    bool
	Timeout  int
}

type Telegram struct {
	options TelegramOptions
	logs    *sre.Logs
	traces  *sre.Traces
	metrics *sre.Metrics
}

func (t *Telegram) Start(wg *sync.WaitGroup) {

}

func NewTelegram(options TelegramOptions, observability *common.Observability) *Telegram {
	return &Telegram{
		options: options,
		logs:    observability.Logs(),
		traces:  observability.Traces(),
		metrics: observability.Metrics(),
	}
}
