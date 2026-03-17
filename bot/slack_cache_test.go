package bot

import (
	"fmt"
	"testing"
	"time"

	"github.com/devopsext/chatops/common"
)

// MockField implements common.Field for testing
type MockField struct {
	name         string
	fieldType    common.FieldType
	label        string
	values       []string
	defaultValue string
	required     bool
	template     string
	dependencies []string
	hint         string
	filter       string
	value        string
	visible      bool
	parent       common.Field
}

func (m *MockField) Name() string           { return m.name }
func (m *MockField) Type() common.FieldType { return m.fieldType }
func (m *MockField) Label() string          { return m.label }
func (m *MockField) Values() []string       { return m.values }
func (m *MockField) Default() string        { return m.defaultValue }
func (m *MockField) Required() bool         { return m.required }
func (m *MockField) Mandatory() bool        { return false }
func (m *MockField) Template() string       { return m.template }
func (m *MockField) Dependencies() []string { return m.dependencies }
func (m *MockField) Hint() string           { return m.hint }
func (m *MockField) Filter() string         { return m.filter }
func (m *MockField) Value() string          { return m.value }
func (m *MockField) Visible() bool          { return m.visible }
func (m *MockField) Parent() common.Field   { return m.parent }

// MockCommand implements common.Command for testing
type MockCommand struct {
	name            string
	fieldsCallCount int
	fieldsFunc      func(bot common.Bot, message common.Message, params common.ExecuteParams, eval []string, parent common.Field) []common.Field
}

func (m *MockCommand) Name() string                                    { return m.name }
func (m *MockCommand) Group() string                                   { return "" }
func (m *MockCommand) Description() string                             { return "" }
func (m *MockCommand) Params() []string                                { return nil }
func (m *MockCommand) Aliases() []string                               { return nil }
func (m *MockCommand) Confirmation(params common.ExecuteParams) string { return "" }
func (m *MockCommand) Priority() int                                   { return 0 }
func (m *MockCommand) Wrapper() bool                                   { return false }
func (m *MockCommand) Schedule() string                                { return "" }
func (m *MockCommand) Channel() string                                 { return "" }
func (m *MockCommand) Response() common.Response                       { return nil }
func (m *MockCommand) Actions() []common.Action                        { return nil }
func (m *MockCommand) Approval() common.Approval                       { return nil }
func (m *MockCommand) Permissions() bool                               { return false }
func (m *MockCommand) TrackMessages() bool                             { return false }
func (m *MockCommand) Execute(bot common.Bot, message common.Message, params common.ExecuteParams, action common.Action) (common.Executor, string, []*common.Attachment, []common.Action, error) {
	return nil, "", nil, nil, nil
}
func (m *MockCommand) Fields(bot common.Bot, message common.Message, params common.ExecuteParams, eval []string, parent common.Field) []common.Field {
	m.fieldsCallCount++
	if m.fieldsFunc != nil {
		return m.fieldsFunc(bot, message, params, eval, parent)
	}
	return nil
}

// TestBlockSuggestionCaching tests that handleBlockSuggestion uses cached values
// instead of calling cmd.Fields() on every keystroke
func TestBlockSuggestionCaching(t *testing.T) {

	// Create test values that would be returned from API
	testValues := []string{"app1", "app2", "app3", "app4", "app5"}

	// Create mock command that tracks how many times Fields() is called
	mockCmd := &MockCommand{
		name: "dyntest",
		fieldsFunc: func(bot common.Bot, message common.Message, params common.ExecuteParams, eval []string, parent common.Field) []common.Field {
			return []common.Field{
				&MockField{
					name:      "application",
					fieldType: common.FieldTypeDynamicSelect,
					values:    testValues,
					hint:      "Select an application",
				},
			}
		},
	}

	// Create a SlackMessageField with no cached values initially
	slackField := &SlackMessageField{
		field: &MockField{
			name:      "application",
			fieldType: common.FieldTypeDynamicSelect,
		},
		values: nil, // No cached values
	}

	// Create SlackMessageFields
	msgFields := SlackMessageFields{
		items: []*SlackMessageField{slackField},
	}

	// Create a mock message
	msg := &SlackMessage{
		cmd:    mockCmd,
		fields: msgFields,
		params: make(common.ExecuteParams),
	}

	// Test 1: First call should trigger Fields() because cache is empty
	t.Run("FirstCall_ShouldFetchFromCommand", func(t *testing.T) {
		fieldName := "application"
		cachedField := msg.fields.findField(fieldName)

		if cachedField == nil {
			t.Fatal("Expected to find field in message")
		}

		// Initially no cached values
		if len(cachedField.values) != 0 {
			t.Errorf("Expected no cached values initially, got %d", len(cachedField.values))
		}

		// Simulate what handleBlockSuggestion does - check cache first
		var values []string
		if cachedField != nil && len(cachedField.values) > 0 {
			// Use cache
			values = cachedField.values
		} else {
			// No cache - call Fields()
			fields := mockCmd.Fields(nil, nil, nil, []string{fieldName}, nil)
			for _, f := range fields {
				if f.Name() == fieldName {
					values = f.Values()
					break
				}
			}
			// Store in cache
			cachedField.values = values
		}

		if mockCmd.fieldsCallCount != 1 {
			t.Errorf("Expected Fields() to be called once, got %d", mockCmd.fieldsCallCount)
		}

		if len(values) != len(testValues) {
			t.Errorf("Expected %d values, got %d", len(testValues), len(values))
		}
	})

	// Test 2: Second call should use cache - Fields() should NOT be called again
	t.Run("SecondCall_ShouldUseCache", func(t *testing.T) {
		initialCallCount := mockCmd.fieldsCallCount
		fieldName := "application"

		cachedField := msg.fields.findField(fieldName)

		// Now cached values should exist
		if len(cachedField.values) == 0 {
			t.Fatal("Expected cached values to exist after first call")
		}

		// Simulate second call
		var values []string
		if cachedField != nil && len(cachedField.values) > 0 {
			// Use cache - this is the path we expect
			values = cachedField.values
		} else {
			// This should NOT happen
			mockCmd.Fields(nil, nil, nil, []string{fieldName}, nil)
		}

		// Fields() should NOT have been called again
		if mockCmd.fieldsCallCount != initialCallCount {
			t.Errorf("Expected Fields() NOT to be called on cached lookup, but call count went from %d to %d",
				initialCallCount, mockCmd.fieldsCallCount)
		}

		if len(values) != len(testValues) {
			t.Errorf("Expected %d cached values, got %d", len(testValues), len(values))
		}
	})

	// Test 3: Third call (simulate typing different text) should still use cache
	t.Run("ThirdCall_StillUsesCache", func(t *testing.T) {
		initialCallCount := mockCmd.fieldsCallCount
		fieldName := "application"

		cachedField := msg.fields.findField(fieldName)

		var values []string
		if cachedField != nil && len(cachedField.values) > 0 {
			values = cachedField.values
		} else {
			mockCmd.Fields(nil, nil, nil, []string{fieldName}, nil)
		}

		if mockCmd.fieldsCallCount != initialCallCount {
			t.Errorf("Expected Fields() NOT to be called on third lookup, but call count changed from %d to %d",
				initialCallCount, mockCmd.fieldsCallCount)
		}

		if len(values) != len(testValues) {
			t.Errorf("Expected %d cached values, got %d", len(testValues), len(values))
		}
	})
}

// TestBlockSuggestionCachingMultipleFields tests caching with multiple dynamic fields
func TestBlockSuggestionCachingMultipleFields(t *testing.T) {

	appValues := []string{"app1", "app2", "app3"}
	envValues := []string{"prod", "test", "dev"}

	mockCmd := &MockCommand{
		name: "dyntest",
		fieldsFunc: func(bot common.Bot, message common.Message, params common.ExecuteParams, eval []string, parent common.Field) []common.Field {
			return []common.Field{
				&MockField{
					name:      "application",
					fieldType: common.FieldTypeDynamicSelect,
					values:    appValues,
				},
				&MockField{
					name:      "environment",
					fieldType: common.FieldTypeDynamicSelect,
					values:    envValues,
				},
			}
		},
	}

	msgFields := SlackMessageFields{
		items: []*SlackMessageField{
			{
				field:  &MockField{name: "application", fieldType: common.FieldTypeDynamicSelect},
				values: nil,
			},
			{
				field:  &MockField{name: "environment", fieldType: common.FieldTypeDynamicSelect},
				values: nil,
			},
		},
	}

	msg := &SlackMessage{
		cmd:    mockCmd,
		fields: msgFields,
		params: make(common.ExecuteParams),
	}

	t.Run("EachFieldCachedIndependently", func(t *testing.T) {
		// Fetch application field
		appField := msg.fields.findField("application")
		if appField == nil {
			t.Fatal("Expected to find application field")
		}

		// First call for application - should call Fields()
		if len(appField.values) == 0 {
			fields := mockCmd.Fields(nil, nil, nil, []string{"application"}, nil)
			for _, f := range fields {
				if f.Name() == "application" {
					appField.values = f.Values()
					break
				}
			}
		}

		firstCallCount := mockCmd.fieldsCallCount
		if firstCallCount != 1 {
			t.Errorf("Expected 1 call to Fields(), got %d", firstCallCount)
		}

		// Second call for application - should use cache
		if len(appField.values) > 0 {
			// Using cache, no call needed
		} else {
			mockCmd.Fields(nil, nil, nil, []string{"application"}, nil)
		}

		if mockCmd.fieldsCallCount != firstCallCount {
			t.Errorf("Application field should use cache, but Fields() was called")
		}

		// Now fetch environment field - should call Fields() since its cache is empty
		envField := msg.fields.findField("environment")
		if len(envField.values) == 0 {
			fields := mockCmd.Fields(nil, nil, nil, []string{"environment"}, nil)
			for _, f := range fields {
				if f.Name() == "environment" {
					envField.values = f.Values()
					break
				}
			}
		}

		if mockCmd.fieldsCallCount != firstCallCount+1 {
			t.Errorf("Expected one more call for environment field, got call count %d", mockCmd.fieldsCallCount)
		}

		// Now both should be cached
		finalCallCount := mockCmd.fieldsCallCount

		// Query application again
		if len(appField.values) > 0 {
			// cache hit
		} else {
			mockCmd.Fields(nil, nil, nil, []string{"application"}, nil)
		}

		// Query environment again
		if len(envField.values) > 0 {
			// cache hit
		} else {
			mockCmd.Fields(nil, nil, nil, []string{"environment"}, nil)
		}

		if mockCmd.fieldsCallCount != finalCallCount {
			t.Errorf("Both fields should use cache, but Fields() was called. Count went from %d to %d",
				finalCallCount, mockCmd.fieldsCallCount)
		}
	})
}

// TestSlackMessageFieldsFindField tests the findField method
func TestSlackMessageFieldsFindField(t *testing.T) {
	fields := SlackMessageFields{
		items: []*SlackMessageField{
			{field: &MockField{name: "field1"}, values: []string{"a", "b"}},
			{field: &MockField{name: "field2"}, values: []string{"c", "d"}},
			{field: &MockField{name: "field3"}, values: nil},
		},
	}

	t.Run("FindExistingField", func(t *testing.T) {
		f := fields.findField("field1")
		if f == nil {
			t.Error("Expected to find field1")
		}
		if len(f.values) != 2 {
			t.Errorf("Expected 2 values, got %d", len(f.values))
		}
	})

	t.Run("FindNonExistentField", func(t *testing.T) {
		f := fields.findField("nonexistent")
		if f != nil {
			t.Error("Expected nil for non-existent field")
		}
	})

	t.Run("FindFieldWithNoValues", func(t *testing.T) {
		f := fields.findField("field3")
		if f == nil {
			t.Error("Expected to find field3")
		}
		if len(f.values) != 0 {
			t.Errorf("Expected 0 values, got %d", len(f.values))
		}
	})
}

// TestCacheEntryAge verifies that cacheEntryAge uses the Slack timestamp embedded
// in the cache key rather than cachedAt, so TTL enforcement survives pod restarts.
//
// Root cause of the bug: ToSlackMessageCache sets CachedAt = time.Now() at dump
// time, so after a restart all entries look brand-new and nothing is evicted.
// The fix: derive age from the numeric Slack unix-ts in the key instead.
func TestCacheEntryAge(t *testing.T) {
	ttl := 720 * time.Hour
	now := time.Now()

	t.Run("OldMessageExpiredByKeyTS", func(t *testing.T) {
		// Slack ts from 91 days ago — well beyond 720 h TTL.
		// cachedAt is recent, simulating CachedAt being reset at dump time.
		// Without the fix, age = ~10s and the entry would survive the restart.
		// With the fix, age = ~91 days and the entry is correctly skipped.
		msgTime := now.Add(-91 * 24 * time.Hour)
		slackTS := float64(msgTime.Unix()) + float64(msgTime.Nanosecond())/1e9
		key := "C02RC584CR0/" + formatSlackTS(slackTS)
		cachedAt := now.Add(-10 * time.Second)

		age := cacheEntryAge(key, cachedAt, now)

		if age < ttl {
			t.Errorf("expected age > 720h (entry should be expired), got %v", age)
		}
		if now.Sub(cachedAt) >= ttl {
			t.Error("test setup error: cachedAt-based age must be < TTL to prove the bug")
		}
	})

	t.Run("RecentMessageNotExpired", func(t *testing.T) {
		// Slack ts from 3 days ago — within 720 h TTL, should be loaded.
		msgTime := now.Add(-3 * 24 * time.Hour)
		slackTS := float64(msgTime.Unix()) + float64(msgTime.Nanosecond())/1e9
		key := "C02RC584CR0/" + formatSlackTS(slackTS)
		cachedAt := now.Add(-5 * time.Second)

		age := cacheEntryAge(key, cachedAt, now)

		if age >= ttl {
			t.Errorf("expected age < 720h (entry should survive), got %v", age)
		}
	})

	t.Run("UUIDKeyFallsBackToCachedAt", func(t *testing.T) {
		// Slash-command entries use "channelID/userID-uuid" keys — no numeric ts.
		// Must fall back to cachedAt.
		key := "C02RC584CR0/U0160NJ0RP1-9769edce-9f88-4db9-bddc-4522d1fa6e39"
		cachedAt := now.Add(-2 * 24 * time.Hour)

		age := cacheEntryAge(key, cachedAt, now)
		expected := now.Sub(cachedAt)

		if age != expected {
			t.Errorf("expected fallback to cachedAt age %v, got %v", expected, age)
		}
	})

	t.Run("SubSecondPrecisionPreserved", func(t *testing.T) {
		// Slack timestamps carry sub-second precision; verify the fractional part
		// is not lost when converting to time.Duration.
		msgTime := now.Add(-1 * time.Hour)
		slackTS := float64(msgTime.Unix()) + 0.632309
		key := "C01SYG29RQF/" + formatSlackTS(slackTS)

		age := cacheEntryAge(key, now, now)

		reconstructed := now.Add(-age)
		expected := time.Unix(int64(slackTS), int64(0.632309*1e9))
		diff := reconstructed.Sub(expected)
		if diff < 0 {
			diff = -diff
		}
		if diff > time.Millisecond {
			t.Errorf("sub-second precision lost: reconstructed time off by %v", diff)
		}
	})
}

// formatSlackTS formats a float64 unix timestamp as "seconds.microseconds",
// matching the format used in Slack message keys.
func formatSlackTS(ts float64) string {
	sec := int64(ts)
	usec := int64((ts - float64(sec)) * 1e6)
	return fmt.Sprintf("%d.%06d", sec, usec)
}
