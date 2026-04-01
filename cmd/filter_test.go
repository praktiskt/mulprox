package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestStringSliceFromViper(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "single value",
			input:    []string{"Sweden"},
			expected: []string{"Sweden"},
		},
		{
			name:     "comma-separated single element",
			input:    []string{"Sweden,Finland"},
			expected: []string{"Sweden", "Finland"},
		},
		{
			name:     "already split",
			input:    []string{"Sweden", "Finland"},
			expected: []string{"Sweden", "Finland"},
		},
		{
			name:     "single element with multiple commas",
			input:    []string{"Sweden,Finland,Norway"},
			expected: []string{"Sweden", "Finland", "Norway"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.Set("test", tt.input)

			var result []string
			raw := v.GetStringSlice("test")
			if len(raw) == 1 && strings.Contains(raw[0], ",") {
				result = strings.Split(raw[0], ",")
			} else {
				result = raw
			}

			if len(result) != len(tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("expected %v, got %v", tt.expected, result)
					return
				}
			}
		})
	}
}
