package common

type Processor interface {
	Name() string
	Contains(command string) Executor
}
