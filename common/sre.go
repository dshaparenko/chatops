package common

import (
	sre "github.com/devopsext/sre/common"
)

type Observability struct {
	logs    *sre.Logs
	traces  *sre.Traces
	metrics *sre.Metrics
}

func (o *Observability) Logs() *sre.Logs {
	return o.logs
}

func (o *Observability) Traces() *sre.Traces {
	return o.traces
}

func (o *Observability) Metrics() *sre.Metrics {
	return o.metrics
}

func NewObservability(logs *sre.Logs, traces *sre.Traces, metrics *sre.Metrics) *Observability {

	return &Observability{
		logs:    logs,
		traces:  traces,
		metrics: metrics,
	}
}
