package cmd

import (
	"github.com/devopsext/chatops/processor"
	"github.com/spf13/pflag"
)

var grafanaOptions = processor.GrafanaOptions{
	Name:   envGet("GRAFANA_NAME", "grafana").(string),
	Config: envGet("GRAFANA_CONFIG", "grafana.yml").(string),
}

func SetGrafanaFlags(flags *pflag.FlagSet) {

	flags.StringVar(&grafanaOptions.Name, "grafana-name", grafanaOptions.Name, "Grafana name")
	flags.StringVar(&grafanaOptions.Config, "grafana-config", grafanaOptions.Config, "Grafana config")
}
