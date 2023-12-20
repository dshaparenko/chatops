package processor

import (
	"strings"

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

func (k *K8s) Contains(command string) common.Executor {
	if strings.ToLower(command) == k.Name() {
		return k
	}
	return nil
}

func (k *K8s) Execute(bot common.Bot, command string, payload, args interface{}, send common.ExecutorSendFunc) (bool, error) {

	return false, nil
}

func NewK8s(options K8sOptions, observability *common.Observability) *K8s {

	logger := observability.Logs()

	return &K8s{
		options: options,
		logger:  logger,
	}
}
