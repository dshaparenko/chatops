package common

import "github.com/devopsext/utils"

type User interface {
	ID() string
	Name() string
	TimeZone() string
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
	Name     string
	Type     FieldType
	Label    string
	Default  string
	Hint     string
	Required bool
	Values   []string
	Template string
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
	Fields(bot Bot, message Message) []Field
	Priority() int
	Wrapper() bool
	Schedule() string
	Channel() string
	Execute(bot Bot, message Message, params ExecuteParams) (Executor, string, []*Attachment, error)
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
