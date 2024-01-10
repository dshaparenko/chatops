package common

import "github.com/devopsext/utils"

type User interface {
	ID() string
	Name() string
}

type Attachment struct {
	Title string
	Text  string
	Data  []byte
}

type ExecuteParams = map[string]string

type Command interface {
	Name() string
	Description() string
	Params() []string
	Execute(bot Bot, user User, params ExecuteParams) (string, []*Attachment, error)
}

type Processor interface {
	Name() string
	Commands() []Command
}

type Processors struct {
	list []Processor
}

func (ps *Processors) Add(p Processor) {
	if !utils.IsEmpty(p) {
		ps.list = append(ps.list, p)
	}
}

func (ps *Processors) AddList(list []Processor) {
	ps.list = append(ps.list, list...)
}

func (ps *Processors) Items() []Processor {
	return ps.list
}

func NewProcessors() *Processors {
	return &Processors{}
}
