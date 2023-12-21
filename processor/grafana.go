package processor

import (
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

func NewGrafana(options GrafanaOptions, observability *common.Observability) *Grafana {

	logger := observability.Logs()

	return &Grafana{
		options: options,
		logger:  logger,
	}
}
