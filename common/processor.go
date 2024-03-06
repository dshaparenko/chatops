package common

import "github.com/devopsext/utils"

type User interface {
	ID() string
	Name() string
	TimeZone() string
}

type Message interface {
	ID() string
	Visible() bool
	User() User
}

type Channel interface {
	ID() string
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
}

type FieldType string

type Field struct {
	Name     string
	Type     FieldType
	Label    string
	Default  string
	Hint     string
	Required bool
	Values   []string
}

type Executor interface {
	After(message Message, channel Channel) error
}

type Command interface {
	Name() string
	Description() string
	Params() []string
	Aliases() []string
	Response() Response
	Fields() []Field
	Execute(bot Bot, user User, params ExecuteParams) (Executor, string, []*Attachment, error)
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
	FieldTypeUnknown     = ""
	FieldTypeEdit        = "edit"
	FieldTypeMultiEdit   = "multiedit"
	FieldTypeInteger     = "integer"
	FieldTypeFloat       = "float"
	FieldTypeURL         = "url"
	FieldTypeDate        = "date"
	FieldTypeTime        = "time"
	FieldTypeSelect      = "select"
	FieldTypeMultiSelect = "multiselect"
	FieldTypeBool        = "bool"
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

func NewProcessors() *Processors {
	return &Processors{}
}
