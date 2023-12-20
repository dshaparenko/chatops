package processor

import (
	"strings"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
)

type GrafanaOptions struct {
	Name   string
	Config string
}

type Grafana struct {
	options GrafanaOptions
	logger  sreCommon.Logger
}

func (g *Grafana) Name() string {
	return g.options.Name
}

func (g *Grafana) Contains(command string) common.Executor {
	if strings.ToLower(command) == g.Name() {
		return g
	}
	return nil
}

func (g *Grafana) Execute(bot common.Bot, command string, payload, args interface{}, send common.ExecutorSendFunc) (bool, error) {

	return false, nil
}

func NewGrafana(options GrafanaOptions, observability *common.Observability) *Grafana {

	logger := observability.Logs()

	return &Grafana{
		options: options,
		logger:  logger,
	}
}
