package common

import "github.com/devopsext/utils"

type User interface {
	ID() string
	Name() string
}

type AttachmentType string

type Attachment struct {
	Title string
	Text  string
	Data  []byte
	Type  AttachmentType
}

type ExecuteParams = map[string]string

type Response struct {
	Visible  bool // visible for others, not only you
	Duration bool // show duration in replay
	Original bool // show orignal as quote
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

type Command interface {
	Name() string
	Description() string
	Params() []string
	Aliases() []string
	Response() Response
	Fields() []Field
	Execute(bot Bot, user User, params ExecuteParams) (string, []*Attachment, error)
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
