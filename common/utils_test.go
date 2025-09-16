package common

import (
	"reflect"
	"testing"
)

func TestRemoveEmptyStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "Slice with empty strings",
			input:    []string{"", "test", "", "example", "  "},
			expected: []string{"test", "example"},
		},
		{
			name:     "Slice with spaces",
			input:    []string{" test ", "  example  "},
			expected: []string{"test", "example"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveEmptyStrings(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("RemoveEmptyStrings() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetStringKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected []string
	}{
		{
			name:     "Empty map",
			input:    map[string]interface{}{},
			expected: nil,
		},
		{
			name: "Map with keys",
			input: map[string]interface{}{
				"key1": "value1",
				"key2": 2,
				"key3": true,
			},
			expected: []string{"key1", "key2", "key3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetStringKeys(tt.input)
			// Sort both slices to ensure a consistent comparison
			if len(result) != len(tt.expected) {
				t.Errorf("GetStringKeys() = %v, want %v", result, tt.expected)
				return
			}

			// Check if all expected keys are in the result
			resultMap := make(map[string]bool)
			for _, k := range result {
				resultMap[k] = true
			}

			for _, k := range tt.expected {
				if !resultMap[k] {
					t.Errorf("GetStringKeys() missing key %s", k)
				}
			}
		})
	}
}
