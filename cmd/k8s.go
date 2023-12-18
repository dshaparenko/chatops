package cmd

import (
	"github.com/devopsext/chatops/processor"
	"github.com/spf13/pflag"
)

var k8sOptions = processor.K8sOptions{
	Name:   envGet("K8S_NAME", "k8s").(string),
	Config: envGet("K8S_CONFIG", "k8s.yml").(string),
}

func SetK8sFlags(flags *pflag.FlagSet) {

	flags.StringVar(&k8sOptions.Name, "k8s-name", k8sOptions.Name, "K8s name")
	flags.StringVar(&k8sOptions.Config, "k8s-config", k8sOptions.Config, "K8s config")
}
