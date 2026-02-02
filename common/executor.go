package common

// CommandExecutor provides an interface for executing commands
// without direct dependency on specific bot implementations.
type CommandExecutor interface {
	// ExecuteCommand triggers a command execution on the specified bot.
	// Returns the Message (use Message.ID() for tracking) or nil if no message was created.
	ExecuteCommand(botName, channel, command, userID string) (Message, error)
	// GetMessageStatus returns the status of a message by its ID.
	GetMessageStatus(botName, messageID string) (MessageStatus, error)
}

// GenericUser is a simple implementation of the User interface
type GenericUser struct {
	id       string
	name     string
	timezone string
	commands []string
}

func (u *GenericUser) ID() string {
	return u.id
}

func (u *GenericUser) Name() string {
	return u.name
}

func (u *GenericUser) TimeZone() string {
	return u.timezone
}

func (u *GenericUser) Commands() []string {
	return u.commands
}

func NewGenericUser(id, name, timezone string, commands []string) *GenericUser {
	if commands == nil {
		commands = []string{}
	}
	return &GenericUser{
		id:       id,
		name:     name,
		timezone: timezone,
		commands: commands,
	}
}

type GenericResponse struct {
	visible  bool
	duration bool
	original bool
	err      bool
	iconURL  string
}

func (r *GenericResponse) Visible() bool {
	return r.visible
}

func (r *GenericResponse) Duration() bool {
	return r.duration
}

func (r *GenericResponse) Original() bool {
	return r.original
}

func (r *GenericResponse) Error() bool {
	return r.err
}

func (r *GenericResponse) IconURL() string {
	return r.iconURL
}

func NewGenericResponse(visible bool) *GenericResponse {
	return &GenericResponse{
		visible:  visible,
		duration: false,
		original: false,
		err:      false,
		iconURL:  "",
	}
}
