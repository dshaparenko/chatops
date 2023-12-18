package common

import (
	sre "github.com/devopsext/sre/common"
)

type Observability struct {
	logs    *sre.Logs
	metrics *sre.Metrics
}

func (o *Observability) Info(obj interface{}, args ...interface{}) {
	if o.logs != nil {
		o.logs.Info(obj, args...)
	}
}

func (o *Observability) Warn(obj interface{}, args ...interface{}) {
	if o.logs != nil {
		o.logs.Warn(obj, args...)
	}
}

func (o *Observability) Debug(obj interface{}, args ...interface{}) {
	if o.logs != nil {
		o.logs.Debug(obj, args...)
	}
}

func (o *Observability) Error(obj interface{}, args ...interface{}) {
	if o.logs != nil {
		o.logs.Error(obj, args...)
	}
}

func (o *Observability) Logs() *sre.Logs {
	return o.logs
}

func (o *Observability) Metrics() *sre.Metrics {
	return o.metrics
}

func NewObservability(logs *sre.Logs, metrics *sre.Metrics) *Observability {

	return &Observability{
		logs:    logs,
		metrics: metrics,
	}
}
