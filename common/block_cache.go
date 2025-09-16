package common

import (
	"encoding/json"
	"fmt"

	"github.com/slack-go/slack"
)

// BlockCache is a serializable representation of a slack.Block
// It allows for proper serialization and deserialization of Block objects
type BlockCache struct {
	// Type of the block
	Type string `json:"type"`

	// Block ID if present
	BlockID string `json:"block_id,omitempty"`

	// Raw JSON data of the block for complete serialization
	RawData json.RawMessage `json:"raw_data,omitempty"`

	// Additional type-specific fields for special block types
	// We store these separately to facilitate easier reconstruction

	// For button blocks within action blocks
	ActionElements []ActionElementCache `json:"action_elements,omitempty"`

	// For text blocks
	Text *TextBlockCache `json:"text,omitempty"`

	// For image blocks
	ImageURL string `json:"image_url,omitempty"`
	AltText  string `json:"alt_text,omitempty"`

	// For file blocks
	FileID     string `json:"file_id,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
	Source     string `json:"source,omitempty"`
}

// TextBlockCache represents slack.TextBlockObject in a serializable form
type TextBlockCache struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	Emoji    bool   `json:"emoji,omitempty"`
	Verbatim bool   `json:"verbatim,omitempty"`
}

// ActionElementCache represents button elements in a serializable form
type ActionElementCache struct {
	Type     string          `json:"type"`
	ActionID string          `json:"action_id"`
	Text     *TextBlockCache `json:"text,omitempty"`
	Value    string          `json:"value,omitempty"`
	URL      string          `json:"url,omitempty"`
	Style    string          `json:"style,omitempty"`
}

// TextBlockObjectToCache converts a slack.TextBlockObject to a TextBlockCache
func TextBlockObjectToCache(text *slack.TextBlockObject) *TextBlockCache {
	if text == nil {
		return nil
	}

	return &TextBlockCache{
		Type:     string(text.Type),
		Text:     text.Text,
		Emoji:    text.Emoji,
		Verbatim: text.Verbatim,
	}
}

// CacheToTextBlockObject converts a TextBlockCache back to a slack.TextBlockObject
func CacheToTextBlockObject(cache *TextBlockCache) *slack.TextBlockObject {
	if cache == nil {
		return nil
	}

	return slack.NewTextBlockObject(
		cache.Type,
		cache.Text,
		cache.Emoji,
		cache.Verbatim,
	)
}

// BlockToCache converts a slack.Block to a BlockCache
func BlockToCache(block slack.Block) (*BlockCache, error) {
	if block == nil {
		return nil, nil
	}

	// Create base cache with type information
	cache := &BlockCache{
		Type: string(block.BlockType()),
	}

	// Store raw data for complete serialization
	rawData, err := json.Marshal(block)
	if err == nil {
		cache.RawData = rawData
	}

	// Extract type-specific information based on block type
	switch b := block.(type) {
	case *slack.ActionBlock:
		cache.BlockID = b.BlockID

		// Extract button elements
		if b.Elements != nil && len(b.Elements.ElementSet) > 0 {
			cache.ActionElements = make([]ActionElementCache, 0, len(b.Elements.ElementSet))

			for _, elem := range b.Elements.ElementSet {
				if button, ok := elem.(*slack.ButtonBlockElement); ok {
					actionElement := ActionElementCache{
						Type:     string(button.Type),
						ActionID: button.ActionID,
						Value:    button.Value,
						URL:      button.URL,
					}

					if button.Style != "" {
						actionElement.Style = string(button.Style)
					}

					if button.Text != nil {
						actionElement.Text = TextBlockObjectToCache(button.Text)
					}

					cache.ActionElements = append(cache.ActionElements, actionElement)
				}
			}
		}
	case *slack.SectionBlock:
		cache.BlockID = b.BlockID
		if b.Text != nil {
			cache.Text = TextBlockObjectToCache(b.Text)
		}
	case *slack.ImageBlock:
		cache.BlockID = b.BlockID
		cache.ImageURL = b.ImageURL
		cache.AltText = b.AltText
		if b.Title != nil {
			cache.Text = TextBlockObjectToCache(b.Title)
		}
	}

	return cache, nil
}

// CacheToBlock converts a BlockCache back to a slack.Block
func CacheToBlock(cache *BlockCache) (slack.Block, error) {
	if cache == nil {
		return nil, nil
	}

	// Create the appropriate block type based on the stored type
	switch slack.MessageBlockType(cache.Type) {
	case slack.MBTAction:
		// Recreate an action block with its elements
		elements := make([]slack.BlockElement, 0)

		for _, elem := range cache.ActionElements {
			if elem.Type == "button" {
				button := &slack.ButtonBlockElement{
					Type:     slack.MessageElementType(elem.Type),
					ActionID: elem.ActionID,
					Value:    elem.Value,
					URL:      elem.URL,
				}

				if elem.Style != "" {
					button.Style = slack.Style(elem.Style)
				}

				if elem.Text != nil {
					button.Text = CacheToTextBlockObject(elem.Text)
				}

				elements = append(elements, button)
			}
		}

		return slack.NewActionBlock(cache.BlockID, elements...), nil

	case slack.MBTSection:
		// Recreate a section block
		block := &slack.SectionBlock{
			Type:    slack.MBTSection,
			BlockID: cache.BlockID,
		}

		if cache.Text != nil {
			block.Text = CacheToTextBlockObject(cache.Text)
		}

		return block, nil

	case slack.MBTImage:
		// Recreate an image block
		block := &slack.ImageBlock{
			Type:     slack.MBTImage,
			BlockID:  cache.BlockID,
			ImageURL: cache.ImageURL,
			AltText:  cache.AltText,
		}

		if cache.Text != nil {
			block.Title = CacheToTextBlockObject(cache.Text)
		}

		return block, nil

	case slack.MBTDivider:
		// Divider blocks are simple
		return slack.NewDividerBlock(), nil

	default:
		// For unknown or unhandled types, try to use the raw data
		if len(cache.RawData) > 0 {
			var block slack.Block

			// This is a best-effort approach and may not work for all block types
			err := json.Unmarshal(cache.RawData, &block)
			if err == nil && block != nil {
				return block, nil
			}

			return nil, fmt.Errorf("failed to deserialize block from raw data: %v", err)
		}

		return nil, fmt.Errorf("unsupported block type: %s", cache.Type)
	}
}

// BlocksToCache converts a slice of slack.Block to a slice of BlockCache
func BlocksToCache(blocks []slack.Block) ([]*BlockCache, error) {
	if len(blocks) == 0 {
		return nil, nil
	}

	result := make([]*BlockCache, 0, len(blocks))
	for _, block := range blocks {
		cache, err := BlockToCache(block)
		if err != nil {
			return nil, err
		}
		if cache != nil {
			result = append(result, cache)
		}
	}

	return result, nil
}

// CacheToBlocks converts a slice of BlockCache back to a slice of slack.Block
func CacheToBlocks(caches []*BlockCache) ([]slack.Block, error) {
	if len(caches) == 0 {
		return nil, nil
	}

	result := make([]slack.Block, 0, len(caches))
	for _, cache := range caches {
		block, err := CacheToBlock(cache)
		if err != nil {
			// Log the error but continue with other blocks
			continue
		}
		if block != nil {
			result = append(result, block)
		}
	}

	return result, nil
}

// BlockCacheAsJSON serializes a list of blocks to a JSON string
func BlockCacheAsJSON(blocks []slack.Block) (string, error) {
	caches, err := BlocksToCache(blocks)
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

// BlockCacheFromJSON deserializes a JSON string to a list of BlockCache objects
func BlockCacheFromJSON(jsonStr string) ([]*BlockCache, error) {
	if jsonStr == "" {
		return nil, nil
	}

	var caches []*BlockCache
	err := json.Unmarshal([]byte(jsonStr), &caches)
	if err != nil {
		return nil, err
	}

	return caches, nil
}
