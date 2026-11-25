package main

import (
	"strings"
)

// missingRequiredEnv returns the names in list (separated by commas and/or
// whitespace) whose environment variable is unset or blank, in list order and
// without duplicates.
//
// It backs -require-env: a deployment names the variables it cannot run without,
// and the gateway refuses to start when one is missing, instead of starting healthy
// with a feature silently off. An empty ZG_GATEWAY_CLIENT_IP_KEY, for one, turns
// off the signed client address and puts every user in the router's single
// rate-limit bucket; an empty ZG_GATEWAY_ALLOWED_ORIGINS turns off browser access.
// Both are valid choices locally, so their flags cannot treat empty as an error;
// only the deployment knows they are required. Phala enforces the same thing outside
// the process (CVM_REQUIRED_KEYS in deploy/phala); tapp has no such hook.
//
// Only names are ever reported, never values: the list typically names secrets.
func missingRequiredEnv(list string, lookup func(string) (string, bool)) []string {
	var missing []string
	seen := map[string]bool{}
	for _, name := range strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if seen[name] {
			continue
		}
		seen[name] = true
		if v, ok := lookup(name); !ok || strings.TrimSpace(v) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}
