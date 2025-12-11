package bot

import (
	"encoding/json"
	"time"

	"github.com/devopsext/chatops/common"
)

// SlackMessageCache is a simplified version of SlackMessage for caching purposes.
// It contains only the essential fields needed for caching and is designed for easy serialization.
type SlackMessageCache struct {
	// Basic identification
	Type        string `json:"type"`
	CommandText string `json:"command_text,omitempty"`
	CommandName string `json:"command_name,omitempty"`
	WrapperName string `json:"wrapper_name,omitempty"`

	// Keys
	OriginChannelID string `json:"origin_channel_id,omitempty"`
	OriginTimestamp string `json:"origin_timestamp,omitempty"`
	OriginThreadTS  string `json:"origin_thread_ts,omitempty"`
	ChannelID       string `json:"channel_id,omitempty"`
	Timestamp       string `json:"timestamp,omitempty"`
	ThreadTS        string `json:"thread_ts,omitempty"`

	// User information
	UserID         string `json:"user_id,omitempty"`
	UserName       string `json:"user_name,omitempty"`
	UserTimeZone   string `json:"user_timezone,omitempty"`
	CallerID       string `json:"caller_id,omitempty"`
	CallerName     string `json:"caller_name,omitempty"`
	CallerTimeZone string `json:"caller_timezone,omitempty"`
	BotID          string `json:"bot_id,omitempty"`

	// Message properties
	Visible     bool   `json:"visible"`
	ResponseURL string `json:"response_url,omitempty"`

	// Serialized fields (complex types serialized to JSON strings)
	SerializedBlocks  string `json:"blocks,omitempty"`
	SerializedActions string `json:"actions,omitempty"`
	SerializedParams  string `json:"params,omitempty"`
	SerializedFields  string `json:"fields,omitempty"`

	// Message tags for grouping and bulk operations
	Tags map[string]string `json:"tags,omitempty"`

	// Timestamp for when this cache entry was created
	CachedAt time.Time `json:"cached_at"`
}

// ToSlackMessageCache converts a SlackMessage to a SlackMessageCache for serialization
func ToSlackMessageCache(sm *SlackMessage) (*SlackMessageCache, error) {
	if sm == nil {
		return nil, nil
	}

	cache := &SlackMessageCache{
		Type:        sm.typ,
		CommandText: sm.cmdText,
		Visible:     sm.visible,
		ResponseURL: sm.responseURL,
		BotID:       sm.botID,
		CachedAt:    time.Now(),
	}

	// Command and wrapper names
	if sm.cmd != nil {
		cache.CommandName = sm.cmd.Name()
	}
	if sm.wrapper != nil {
		cache.WrapperName = sm.wrapper.Name()
	}

	// Origin key
	if sm.originKey != nil {
		cache.OriginChannelID = sm.originKey.channelID
		cache.OriginTimestamp = sm.originKey.timestamp
		cache.OriginThreadTS = sm.originKey.threadTS
	}

	// Current key
	if sm.key != nil {
		cache.ChannelID = sm.key.channelID
		cache.Timestamp = sm.key.timestamp
		cache.ThreadTS = sm.key.threadTS
	}

	// User info
	if sm.user != nil {
		cache.UserID = sm.user.id
		cache.UserName = sm.user.name
		cache.UserTimeZone = sm.user.timezone
	}

	// Caller info
	if sm.caller != nil {
		cache.CallerID = sm.caller.id
		cache.CallerName = sm.caller.name
		cache.CallerTimeZone = sm.caller.timezone
	}

	// Serialize complex objects to JSON
	if len(sm.blocks) > 0 {
		blocksJSON, err := common.BlockCacheAsJSON(sm.blocks)
		if err == nil {
			cache.SerializedBlocks = blocksJSON
		}
	}

	if len(sm.actions) > 0 {
		actionsJSON, err := common.ActionCacheAsJSON(sm.actions)
		if err == nil {
			cache.SerializedActions = actionsJSON
		}
	}

	if len(sm.params) > 0 {
		paramsJSON, err := json.Marshal(sm.params)
		if err == nil {
			cache.SerializedParams = string(paramsJSON)
		}
	}

	if len(sm.fields.items) > 0 {
		// For fields, we store just the essential info needed to reconstruct
		fieldsSimplified := make([]map[string]interface{}, len(sm.fields.items))
		for i, field := range sm.fields.items {
			fieldMap := map[string]interface{}{
				"value": field.value,
				// "values": field.values, disabling while list
			}

			// Only store field name if available
			if field.field != nil {
				fieldMap["name"] = field.field.Name()
			}

			fieldsSimplified[i] = fieldMap
		}

		fieldsJSON, err := json.Marshal(fieldsSimplified)
		if err == nil {
			cache.SerializedFields = string(fieldsJSON)
		}
	}

	// Copy tags
	if len(sm.tags) > 0 {
		cache.Tags = make(map[string]string)
		for k, v := range sm.tags {
			cache.Tags[k] = v
		}
	}

	return cache, nil
}

// FromSlackMessageCache converts a SlackMessageCache back to a SlackMessage
// Note: This requires the Slack instance to fully reconstruct, as some fields
// need to be re-populated by the Slack instance
func FromSlackMessageCache(cache *SlackMessageCache, slack *Slack) (*SlackMessage, error) {
	if cache == nil || slack == nil {
		return nil, nil
	}

	sm := &SlackMessage{
		slack:       slack,
		typ:         cache.Type,
		cmdText:     cache.CommandText,
		visible:     cache.Visible,
		responseURL: cache.ResponseURL,
		botID:       cache.BotID,
	}

	// Reconstruct keys
	sm.originKey = &SlackMessageKey{
		channelID: cache.OriginChannelID,
		timestamp: cache.OriginTimestamp,
		threadTS:  cache.OriginThreadTS,
	}

	sm.key = &SlackMessageKey{
		channelID: cache.ChannelID,
		timestamp: cache.Timestamp,
		threadTS:  cache.ThreadTS,
	}

	// Reconstruct user
	if cache.UserID != "" {
		sm.user = &SlackUser{
			id:       cache.UserID,
			name:     cache.UserName,
			timezone: cache.UserTimeZone,
		}
	}

	// Reconstruct caller
	if cache.CallerID != "" {
		sm.caller = &SlackUser{
			id:       cache.CallerID,
			name:     cache.CallerName,
			timezone: cache.CallerTimeZone,
		}
	}

	// Command and wrapper references need to be looked up from processors
	if cache.CommandName != "" && slack.processors != nil {
		sm.cmd = slack.processors.FindCommand("", cache.CommandName)
	}

	if cache.WrapperName != "" && slack.processors != nil {
		sm.wrapper = slack.processors.FindCommand("", cache.WrapperName)
	}

	// Deserialize params
	if cache.SerializedParams != "" {
		var params map[string]interface{}
		if err := json.Unmarshal([]byte(cache.SerializedParams), &params); err == nil {
			sm.params = params
		}
	}

	// Deserialize blocks if available
	if cache.SerializedBlocks != "" {
		blockCaches, err := common.BlockCacheFromJSON(cache.SerializedBlocks)
		if err != nil {
			slack.logger.Error("Failed to deserialize blocks: %v", err)
		} else {
			blocks, err := common.CacheToBlocks(blockCaches)
			if err != nil {
				slack.logger.Error("Failed to convert block caches to blocks: %v", err)
			} else {
				sm.blocks = blocks
			}
		}
	}

	// Deserialize actions if available
	if cache.SerializedActions != "" {
		actionCaches, err := common.ActionCacheFromJSON(cache.SerializedActions)
		if err != nil {
			slack.logger.Error("Failed to deserialize actions: %v", err)
		} else {
			sm.actions = common.ActionsFromCaches(actionCaches)
		}
	}

	// Restore tags
	if len(cache.Tags) > 0 {
		sm.tags = make(map[string]string)
		for k, v := range cache.Tags {
			sm.tags[k] = v
		}
	}

	return sm, nil
}
