package common

type ExecuteCallback = func()

type Executor interface {
	Execute(command string, payload, args interface{}, callback ExecuteCallback) (bool, error)
}
