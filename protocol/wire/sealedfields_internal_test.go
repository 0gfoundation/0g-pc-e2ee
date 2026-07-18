package wire

import "testing"

func TestValidateSealedFields(t *testing.T) {
	cases := []struct {
		name    string
		fields  []string
		wantErr bool
	}{
		{"messages only", []string{"messages"}, false},
		{"messages and tools", []string{"messages", "tools"}, false},
		{"empty", nil, true},
		{"missing messages", []string{"tools"}, true},
		{"duplicate", []string{"messages", "messages"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateSealedFields(c.fields)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateSealedFields(%v) err = %v, wantErr %v", c.fields, err, c.wantErr)
			}
		})
	}
}

func TestDefaultSealedFieldsIsValidAndFresh(t *testing.T) {
	if err := validateSealedFields(defaultSealedFields()); err != nil {
		t.Fatalf("default set fails validation: %v", err)
	}
	// Returns a fresh slice each call, so mutating one result cannot corrupt the
	// shared default.
	a := defaultSealedFields()
	a[0] = "tampered"
	if b := defaultSealedFields(); b[0] != "messages" {
		t.Fatalf("default set was mutated across calls: %v", b)
	}
}
