package common

import (
	"testing"

	"github.com/slack-go/slack"
)

// TestBlockSerialization tests the serialization and deserialization of Block objects
func TestBlockSerialization(t *testing.T) {
	// Test with action block containing button
	actionBlock := slack.NewActionBlock(
		"test_block_id",
		slack.NewButtonBlockElement(
			"test_action_id",
			"test_value",
			slack.NewTextBlockObject("plain_text", "Test Button", false, false),
		),
	)

	// Test block serialization
	blockCache, err := BlockToCache(actionBlock)
	if err != nil {
		t.Fatalf("Failed to serialize block: %v", err)
	}

	// Check block type
	if blockCache.Type != string(slack.MBTAction) {
		t.Errorf("Expected block type '%s', got '%s'", slack.MBTAction, blockCache.Type)
	}

	// Check block ID
	if blockCache.BlockID != "test_block_id" {
		t.Errorf("Expected block ID 'test_block_id', got '%s'", blockCache.BlockID)
	}

	// Check action elements
	if len(blockCache.ActionElements) != 1 {
		t.Fatalf("Expected 1 action element, got %d", len(blockCache.ActionElements))
	}

	actionElem := blockCache.ActionElements[0]
	if actionElem.Type != "button" {
		t.Errorf("Expected element type 'button', got '%s'", actionElem.Type)
	}

	if actionElem.ActionID != "test_action_id" {
		t.Errorf("Expected action ID 'test_action_id', got '%s'", actionElem.ActionID)
	}

	if actionElem.Value != "test_value" {
		t.Errorf("Expected value 'test_value', got '%s'", actionElem.Value)
	}

	if actionElem.Text == nil {
		t.Fatalf("Expected non-nil text object")
	}

	if actionElem.Text.Text != "Test Button" {
		t.Errorf("Expected button text 'Test Button', got '%s'", actionElem.Text.Text)
	}

	// Test conversion back to block
	restoredBlock, err := CacheToBlock(blockCache)
	if err != nil {
		t.Fatalf("Failed to convert cache back to block: %v", err)
	}

	// Check block type
	if restoredBlock.BlockType() != slack.MBTAction {
		t.Errorf("Expected restored block type '%s', got '%s'", slack.MBTAction, restoredBlock.BlockType())
	}

	// Check that the restored block is an action block
	actionBlockRestored, ok := restoredBlock.(*slack.ActionBlock)
	if !ok {
		t.Fatalf("Restored block is not an action block")
	}

	// Check block ID
	if actionBlockRestored.BlockID != "test_block_id" {
		t.Errorf("Expected restored block ID 'test_block_id', got '%s'", actionBlockRestored.BlockID)
	}

	// Check that the action block has elements
	if actionBlockRestored.Elements == nil || len(actionBlockRestored.Elements.ElementSet) != 1 {
		t.Fatalf("Expected 1 element in restored block, got %d",
			func() int {
				if actionBlockRestored.Elements == nil {
					return 0
				}
				return len(actionBlockRestored.Elements.ElementSet)
			}())
	}

	// Check that the element is a button
	buttonElement, ok := actionBlockRestored.Elements.ElementSet[0].(*slack.ButtonBlockElement)
	if !ok {
		t.Fatalf("Restored element is not a button element")
	}

	// Check button properties
	if buttonElement.ActionID != "test_action_id" {
		t.Errorf("Expected restored button action ID 'test_action_id', got '%s'", buttonElement.ActionID)
	}

	if buttonElement.Value != "test_value" {
		t.Errorf("Expected restored button value 'test_value', got '%s'", buttonElement.Value)
	}

	if buttonElement.Text == nil {
		t.Fatalf("Expected non-nil text object in restored button")
	}

	if buttonElement.Text.Text != "Test Button" {
		t.Errorf("Expected restored button text 'Test Button', got '%s'", buttonElement.Text.Text)
	}
}

// TestBlockJSONSerialization tests the JSON serialization and deserialization of blocks
func TestBlockJSONSerialization(t *testing.T) {
	// Create test blocks
	blocks := []slack.Block{
		slack.NewActionBlock(
			"action_block_id",
			slack.NewButtonBlockElement(
				"button_action_id",
				"button_value",
				slack.NewTextBlockObject("plain_text", "Action Button", false, false),
			),
		),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", "This is a section block", false, false),
			nil,
			nil,
		),
		slack.NewDividerBlock(),
	}

	// Serialize to JSON
	jsonStr, err := BlockCacheAsJSON(blocks)
	if err != nil {
		t.Fatalf("Failed to serialize blocks to JSON: %v", err)
	}

	// Deserialize from JSON
	blockCaches, err := BlockCacheFromJSON(jsonStr)
	if err != nil {
		t.Fatalf("Failed to deserialize blocks from JSON: %v", err)
	}

	// Check number of blocks
	if len(blockCaches) != 3 {
		t.Fatalf("Expected 3 blocks, got %d", len(blockCaches))
	}

	// Convert back to blocks
	restoredBlocks, err := CacheToBlocks(blockCaches)
	if err != nil {
		t.Fatalf("Failed to convert caches to blocks: %v", err)
	}

	// Check number of restored blocks
	if len(restoredBlocks) != 3 {
		t.Fatalf("Expected 3 restored blocks, got %d", len(restoredBlocks))
	}

	// Check block types
	if restoredBlocks[0].BlockType() != slack.MBTAction {
		t.Errorf("Expected first block to be action block, got %s", restoredBlocks[0].BlockType())
	}

	if restoredBlocks[1].BlockType() != slack.MBTSection {
		t.Errorf("Expected second block to be section block, got %s", restoredBlocks[1].BlockType())
	}

	if restoredBlocks[2].BlockType() != slack.MBTDivider {
		t.Errorf("Expected third block to be divider block, got %s", restoredBlocks[2].BlockType())
	}
}
