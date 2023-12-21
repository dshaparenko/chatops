package processor

import (
	"github.com/devopsext/chatops/common"
	sreCommon "github.com/devopsext/sre/common"
)

type K8sOptions struct {
	Name   string
	Config string
}

type K8s struct {
	options K8sOptions
	logger  sreCommon.Logger
}

func (k *K8s) Name() string {
	return k.options.Name
}

func NewK8s(options K8sOptions, observability *common.Observability) *K8s {

	logger := observability.Logs()

	return &K8s{
		options: options,
		logger:  logger,
	}
}
