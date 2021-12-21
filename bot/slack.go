package bot

import "sync"

type Slack struct {
}

func (s *Slack) Start(wg *sync.WaitGroup) {
}

func NewSlack() *Slack {
	return &Slack{}
}
