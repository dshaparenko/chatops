package common

type Processors struct {
	list []Processor
}

func (ps *Processors) Add(p Processor) {
	if p != nil {
		ps.list = append(ps.list, p)
	}
}

func (ps *Processors) Executor(command string) Executor {

	for _, p := range ps.list {

		e := p.Contains(command)
		if e != nil {
			return e
		}
	}
	return nil
}

func NewProcessors() Processors {
	return Processors{}
}
