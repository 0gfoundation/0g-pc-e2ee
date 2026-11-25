package main

import (
	"reflect"
	"testing"
)

func TestMissingRequiredEnv(t *testing.T) {
	env := map[string]string{
		"SET":   "value",
		"EMPTY": "",
		"BLANK": "  \t",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	tests := []struct {
		name string
		list string
		want []string
	}{
		{"empty list requires nothing", "", nil},
		{"only separators", " , ,\n", nil},
		{"set passes", "SET", nil},
		{"unset fails", "UNSET", []string{"UNSET"}},
		{"set but empty fails", "EMPTY", []string{"EMPTY"}},
		{"whitespace only fails", "BLANK", []string{"BLANK"}},
		{"commas and spaces, list order kept", "UNSET, SET EMPTY,BLANK", []string{"UNSET", "EMPTY", "BLANK"}},
		{"duplicates reported once", "EMPTY,EMPTY", []string{"EMPTY"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := missingRequiredEnv(tt.list, lookup); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("missingRequiredEnv(%q) = %v, want %v", tt.list, got, tt.want)
			}
		})
	}
}
