package processor

import (
	"github.com/devopsext/chatops/common"
	sre "github.com/devopsext/sre/common"
)

type GrafanaInstance struct {
	URL         string `yaml:"url"`
	Timeout     int    `yaml:"timeout"`
	ApiKey      string `yaml:"apiKey"`
	Org         string `yaml:"org"`
	Period      string `yaml:"period"`
	ImageWidth  int    `yaml:"imageWidth"`
	ImageHeight int    `yaml:"imageHeight"`
}

type GrafanaOptions struct {
	instances map[string]*GrafanaInstance
	Name      string
	Config    string
}

type Grafana struct {
	options GrafanaOptions
	logger  sre.Logger
	tracer  sre.Tracer
}

func (g *Grafana) Name() string {
	return g.options.Name
}

func NewGrafana(options GrafanaOptions, observability common.Observability) *Grafana {

	logger := observability.Logs()

	instances := make(map[string]*GrafanaInstance)
	exists, err := common.LoadYaml(options.Config, &instances)
	if err != nil {
		logger.Error(err)
		return nil
	}

	if !exists {
		logger.Debug("Grafana has no config.")
		return nil
	}

	opts := options
	opts.instances = instances

	return &Grafana{
		options: opts,
		logger:  logger,
		tracer:  observability.Traces(),
	}
}
