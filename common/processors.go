package common

import "github.com/devopsext/utils"

type Processors struct {
	list []Processor
}

func (ps *Processors) Add(p Processor) {
	if !utils.IsEmpty(p) {
		ps.list = append(ps.list, p)
	}
}

func (ps *Processors) Items() []Processor {
	return ps.list
}

/*func (ps *Processors) Find(name string, command ...string) Executor {

	for _, p := range ps.list {

		e := p.Contains(command)
		if e != nil {
			return e
		}
	}
	return nil
}*/

func NewProcessors() *Processors {
	return &Processors{}
}
