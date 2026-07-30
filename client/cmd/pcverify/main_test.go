package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type stubRegistry struct {
	signer string
	ack    bool
	err    error
}

func (s stubRegistry) AcknowledgedSigner(context.Context, string) (string, bool, error) {
	return s.signer, s.ack, s.err
}

const (
	prov   = "0xaabbccddeeff00112233445566778899aabbccdd"
	signer = "0x99887766554433221100ffeeddccbbaa99887766"
)

func TestReport(t *testing.T) {
	cases := []struct {
		name         string
		reg          stubRegistry
		expectSigner string
		wantCode     int
		wantContains string
	}{
		{"acknowledged, no expected", stubRegistry{signer: signer, ack: true}, "", 0, "PASS"},
		{"acknowledged, expected matches", stubRegistry{signer: signer, ack: true}, strings.ToUpper(signer), 0, "PASS"},
		{"acknowledged, expected mismatches", stubRegistry{signer: signer, ack: true}, "0x0000000000000000000000000000000000000001", 1, "FAIL"},
		{"unacknowledged", stubRegistry{signer: signer, ack: false}, "", 1, "FAIL"},
		{"lookup error", stubRegistry{err: errors.New("rpc down")}, "", 1, "FAIL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := report(context.Background(), &out, tc.reg, prov, "0xcontract", tc.expectSigner)
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d (out: %s)", code, tc.wantCode, out.String())
			}
			if !strings.Contains(out.String(), tc.wantContains) {
				t.Errorf("output missing %q:\n%s", tc.wantContains, out.String())
			}
		})
	}
}

func TestRun_MissingRequiredFlags(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), &out, []string{"-provider", prov}); code != 2 {
		t.Errorf("missing -chain-rpc-url: exit = %d, want 2", code)
	}
}
