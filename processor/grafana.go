package processor

import (
	"strings"

	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
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
	}
}
