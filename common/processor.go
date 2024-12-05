package common

import "github.com/devopsext/utils"

type User interface {
	ID() string
	Name() string
	TimeZone() string
	Commands() []string
}

type Channel interface {
	ID() string
}

type Message interface {
	ID() string
	Visible() bool
	User() User
	Channel() Channel
	ParentID() string
}

type AttachmentType string

type Attachment struct {
	Title string
	Text  string
	Data  []byte
	Type  AttachmentType
}

type ExecuteParams = map[string]interface{}

type Response interface {
	Visible() bool  // visible for others, not only you
	Duration() bool // show duration in replay
	Original() bool // show orignal as quote
	Error() bool    // show as error
}

type FieldType string

type Field struct {
	Name         string
	Type         FieldType
	Label        string
	Default      string
	Hint         string
	Required     bool
	Values       []string
	Template     string
	Dependencies []string
}

type Approval interface {
	Channel() string
	Message(bot Bot, message Message, params ExecuteParams) string
}

type Executor interface {
	Response() Response
	After(message Message) error
}

type Command interface {
	Name() string
	Description() string
	Params() []string
	Aliases() []string
	Confirmation() string
	Priority() int
	Wrapper() bool
	Schedule() string
	Channel() string
	Response() Response
	Execute(bot Bot, message Message, params ExecuteParams) (Executor, string, []*Attachment, error)
	Fields(bot Bot, message Message, params ExecuteParams, eval []string) []Field
	Approval() Approval
	Permissions() bool
}

type Processor interface {
	Name() string
	Commands() []Command
}

type Processors struct {
	list []Processor
}

const (
	AttachmentTypeUnknown = ""
	AttachmentTypeText    = "text"
	AttachmentTypeImage   = "image"
	AttachmentTypeFile    = "file"
)

const (
	FileTypeUnknown = ""
	FileTypeText    = "text"
	FileTypeImage   = "image"
)

const (
	FieldTypeUnknown            = ""
	FieldTypeEdit               = "edit"
	FieldTypeMultiEdit          = "multiedit"
	FieldTypeInteger            = "integer"
	FieldTypeFloat              = "float"
	FieldTypeURL                = "url"
	FieldTypeDate               = "date"
	FieldTypeTime               = "time"
	FieldTypeSelect             = "select"
	FieldTypeMultiSelect        = "multiselect"
	FieldTypeDynamicSelect      = "dynamicselect"
	FieldTypeDynamicMultiSelect = "dynamicmultiselect"
	FieldTypeBool               = "bool"
)

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

func (ps *Processors) Exists(processor string) bool {

	for _, v := range ps.list {
		g := v.Name()
		if g == processor {
			return true
		}
	}
	return false
}

func (ps *Processors) FindCommand(processor, command string) Command {

	for _, v := range ps.list {
		g := v.Name()
		if g == processor {
			for _, v1 := range v.Commands() {
				c := v1.Name()
				if c == command {
					return v1
				}
			}
		}
	}
	return nil
}

func (ps *Processors) FindCommandByAlias(alias string) (string, Command) {

	for _, v := range ps.list {
		for _, v1 := range v.Commands() {
			als := v1.Aliases()
			if utils.Contains(als, alias) {
				return v.Name(), v1
			}
		}
	}
	return "", nil
}

func NewProcessors() *Processors {
	return &Processors{}
}
