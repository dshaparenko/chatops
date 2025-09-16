package common

import (
	"testing"
)

// TestActionSerialization tests the serialization and deserialization of Action objects
func TestActionSerialization(t *testing.T) {
	// Create a test action
	testAction := &SimpleAction{
		name:     "test-action",
		label:    "Test Action",
		template: "test-template",
		style:    "primary",
	}

	// Test single action serialization
	cache, err := ToActionCache(testAction)
	if err != nil {
		t.Fatalf("Failed to serialize action: %v", err)
	}

	if cache.Name != "test-action" {
		t.Errorf("Expected name 'test-action', got '%s'", cache.Name)
	}

	if cache.Label != "Test Action" {
		t.Errorf("Expected label 'Test Action', got '%s'", cache.Label)
	}

	if cache.Template != "test-template" {
		t.Errorf("Expected template 'test-template', got '%s'", cache.Template)
	}

	if cache.Style != "primary" {
		t.Errorf("Expected style 'primary', got '%s'", cache.Style)
	}

	// Test list serialization
	actions := []Action{testAction}
	jsonStr, err := ActionCacheAsJSON(actions)
	if err != nil {
		t.Fatalf("Failed to serialize actions to JSON: %v", err)
	}

	// Test deserialization
	caches, err := ActionCacheFromJSON(jsonStr)
	if err != nil {
		t.Fatalf("Failed to deserialize actions from JSON: %v", err)
	}

	if len(caches) != 1 {
		t.Fatalf("Expected 1 action, got %d", len(caches))
	}

	if caches[0].Name != "test-action" {
		t.Errorf("Expected name 'test-action', got '%s'", caches[0].Name)
	}

	// Test converting back to Action interface
	reconstructedActions := ActionsFromCaches(caches)
	if len(reconstructedActions) != 1 {
		t.Fatalf("Expected 1 action, got %d", len(reconstructedActions))
	}

	reconstructed := reconstructedActions[0]
	if reconstructed.Name() != "test-action" {
		t.Errorf("Expected name 'test-action', got '%s'", reconstructed.Name())
	}

	if reconstructed.Label() != "Test Action" {
		t.Errorf("Expected label 'Test Action', got '%s'", reconstructed.Label())
	}

	if reconstructed.Template() != "test-template" {
		t.Errorf("Expected template 'test-template', got '%s'", reconstructed.Template())
	}

	if reconstructed.Style() != "primary" {
		t.Errorf("Expected style 'primary', got '%s'", reconstructed.Style())
	}
}

// TestEmptyActionSerialization tests handling of nil and empty actions
func TestEmptyActionSerialization(t *testing.T) {
	// Test nil action
	cache, err := ToActionCache(nil)
	if err != nil {
		t.Fatalf("ToActionCache(nil) returned error: %v", err)
	}
	if cache != nil {
		t.Errorf("Expected nil cache for nil action, got %v", cache)
	}

	// Test empty actions list
	var actions []Action
	jsonStr, err := ActionCacheAsJSON(actions)
	if err != nil {
		t.Fatalf("ActionCacheAsJSON(empty) returned error: %v", err)
	}
	if jsonStr != "" {
		t.Errorf("Expected empty string for empty actions, got '%s'", jsonStr)
	}

	// Test empty JSON string
	caches, err := ActionCacheFromJSON("")
	if err != nil {
		t.Fatalf("ActionCacheFromJSON(\"\") returned error: %v", err)
	}
	if caches != nil {
		t.Errorf("Expected nil caches for empty JSON, got %v", caches)
	}

	// Test converting empty caches
	var emptyCaches []*ActionCache
	emptyActions := ActionsFromCaches(emptyCaches)
	if emptyActions != nil {
		t.Errorf("Expected nil actions for empty caches, got %v", emptyActions)
	}
}
