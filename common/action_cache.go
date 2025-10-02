package common

import (
	"encoding/json"
)

// ActionCache is a serializable representation of the Action interface
// It allows for proper serialization and deserialization of Action objects
type ActionCache struct {
	// Basic properties from the Action interface
	Name     string `json:"name,omitempty"`
	Label    string `json:"label,omitempty"`
	Template string `json:"template,omitempty"`
	Style    string `json:"style,omitempty"`

	// Type information to help with deserialization
	Type string `json:"type,omitempty"`
}

// ToActionCache converts an Action interface to a serializable ActionCache
func ToActionCache(action Action) (*ActionCache, error) {
	if action == nil {
		return nil, nil
	}

	cache := &ActionCache{
		Name:     action.Name(),
		Label:    action.Label(),
		Template: action.Template(),
		Style:    action.Style(),
		Type:     getActionType(action),
	}

	return cache, nil
}

// ToActionCacheList converts a slice of Action interfaces to a serializable slice of ActionCache
func ToActionCacheList(actions []Action) ([]*ActionCache, error) {
	if len(actions) == 0 {
		return nil, nil
	}

	result := make([]*ActionCache, 0, len(actions))
	for _, action := range actions {
		cache, err := ToActionCache(action)
		if err != nil {
			return nil, err
		}
		if cache != nil {
			result = append(result, cache)
		}
	}

	return result, nil
}

// ActionCacheAsJSON serializes a list of actions to a JSON string
func ActionCacheAsJSON(actions []Action) (string, error) {
	caches, err := ToActionCacheList(actions)
	if err != nil {
		return "", err
	}

	if len(caches) == 0 {
		return "", nil
	}

	bytes, err := json.Marshal(caches)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// ActionCacheFromJSON deserializes a JSON string to a list of ActionCache objects
func ActionCacheFromJSON(jsonStr string) ([]*ActionCache, error) {
	if jsonStr == "" {
		return nil, nil
	}

	var caches []*ActionCache
	err := json.Unmarshal([]byte(jsonStr), &caches)
	if err != nil {
		return nil, err
	}

	return caches, nil
}

// getActionType returns a string identifier for the Action implementation type
func getActionType(action Action) string {
	// This is a basic implementation that just uses the package+type name
	// A more sophisticated approach could use reflection to get the actual type
	return "common.Action"
}

// SimpleAction is a basic implementation of the Action interface
// that can be created from an ActionCache
type SimpleAction struct {
	name     string
	label    string
	template string
	style    string
}

func (a *SimpleAction) Name() string {
	return a.name
}

func (a *SimpleAction) Label() string {
	return a.label
}

func (a *SimpleAction) Template() string {
	return a.template
}

func (a *SimpleAction) Style() string {
	return a.style
}

// NewSimpleActionFromCache creates a new SimpleAction from an ActionCache
func NewSimpleActionFromCache(cache *ActionCache) Action {
	if cache == nil {
		return nil
	}

	return &SimpleAction{
		name:     cache.Name,
		label:    cache.Label,
		template: cache.Template,
		style:    cache.Style,
	}
}

// ActionsFromCaches converts a slice of ActionCache to a slice of Action interfaces
func ActionsFromCaches(caches []*ActionCache) []Action {
	if len(caches) == 0 {
		return nil
	}

	actions := make([]Action, 0, len(caches))
	for _, cache := range caches {
		action := NewSimpleActionFromCache(cache)
		if action != nil {
			actions = append(actions, action)
		}
	}

	return actions
}
