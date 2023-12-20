package common

type ResponseAttachement struct {
	Text  string
	Title string
	Data  []byte
}

type Response interface {
	Message() (string, error)
	Attachments() []*ResponseAttachement
}

type ExecuteParams = map[string]string

type Command interface {
	Name() string
	Description() string
	Params() []string
	Execute(bot Bot, params ExecuteParams) (Response, error)
}

type Processor interface {
	Command
	Commands() []Command
}
