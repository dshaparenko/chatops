package processor

import (
	"github.com/devopsext/chatops/common"
	sre "github.com/devopsext/sre/common"
)

type K8sCluster struct {
	// could be a path to file / content of kube config
	KubeConfig interface{} `yaml:"kubeConfig"`
}

type K8sOptions struct {
	clusters map[string]*K8sCluster
	Name     string
	Config   string
}

type K8s struct {
	options K8sOptions
	logger  sre.Logger
	tracer  sre.Tracer
}

func (k *K8s) Name() string {
	return k.options.Name
}

func NewK8s(options K8sOptions, observability common.Observability) *K8s {

	logger := observability.Logs()

	clusters := make(map[string]*K8sCluster)
	exists, err := common.LoadYaml(options.Config, &clusters)
	if err != nil {
		logger.Error(err)
		return nil
	}

	if !exists {
		logger.Debug("K8s has no config.")
		return nil
	}

	opts := options
	opts.clusters = clusters

	return &K8s{
		options: opts,
		logger:  observability.Logs(),
		tracer:  observability.Traces(),
	}
}
