package common

type ExecutorSendFunc = func(text string) bool

type Executor interface {
	Execute(bot Bot, command string, payload, args interface{}, send ExecutorSendFunc) (bool, error)
}
