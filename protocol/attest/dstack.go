package attest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// QuoteResponse is a provider's /v1/quote reply (the dstack / Phala shape).
//
// Only Quote — the hex-encoded Intel TDX quote — is part of the trusted path:
// the quote is the sole artifact Intel signs. The real reply also carries
// event_log, tcb_info, vm_config and app_compose, but NONE of those are signed
// by Intel; they are convenience decodes a caller must not trust directly. A
// verifier re-derives the measurement from the *verified* quote (and, for app
// identity, replays the event log against it) instead of reading tcb_info. Those
// fields are intentionally omitted from this struct so the trusted path cannot
// accidentally depend on them.
type QuoteResponse struct {
	Quote string `json:"quote"`
}

// DecodeQuoteResponse parses a /v1/quote JSON body and returns the raw
// (hex-decoded) TDX quote bytes, ready for verification and structural parsing.
// It does not verify anything — it only unwraps the transport.
func DecodeQuoteResponse(body []byte) ([]byte, error) {
	var qr QuoteResponse
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, fmt.Errorf("attest: decode quote response: %w", err)
	}
	if qr.Quote == "" {
		return nil, fmt.Errorf("attest: quote response has no \"quote\" field")
	}
	raw, err := hex.DecodeString(qr.Quote)
	if err != nil {
		return nil, fmt.Errorf("attest: quote is not valid hex: %w", err)
	}
	return raw, nil
}
