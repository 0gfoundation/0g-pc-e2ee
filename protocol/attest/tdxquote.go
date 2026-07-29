package attest

import "fmt"

// TDX v4 quote layout (Intel). A quote is a 48-byte header followed by the TD
// Quote Body; the measurement registers and report_data live at fixed offsets
// within the body. The constants below are ABSOLUTE offsets into the whole
// quote (header + body).
//
// Body layout, in order: tee_tcb_svn(16) mr_seam(48) mrsigner_seam(48)
// seam_attributes(8) td_attributes(8) xfam(8) MRTD(48) mr_config_id(48)
// mr_owner(48) mr_owner_config(48) RTMR0(48) RTMR1(48) RTMR2(48) RTMR3(48)
// report_data(64). All offsets are checked against a real dstack quote in the
// KAT (see testdata/dstack_quote_prefix.json).
const (
	quoteHeaderLen = 48
	tdBodyLen      = 584 // TD Quote Body length

	// minQuoteLen is the smallest input ParseTDXQuoteBody can read: the header
	// plus the body through report_data. A full quote is longer — the ECDSA
	// signature and PCK certificate chain follow the body — but structural
	// extraction needs only this prefix.
	minQuoteLen = quoteHeaderLen + tdBodyLen // 632

	mrtdOff       = 184
	rtmr0Off      = 376
	rtmr1Off      = 424
	rtmr2Off      = 472
	rtmr3Off      = 520
	reportDataOff = 568
)

// QuoteBody is the structurally-extracted content of a TDX quote: its
// measurement registers and 64-byte report_data. It carries NO judgment about
// whether the quote is genuine.
type QuoteBody struct {
	Measurement Measurement
	ReportData  [reportDataLen]byte
}

// ParseTDXQuoteBody extracts the measurement registers and report_data from a
// raw TDX quote by fixed offset.
//
// SECURITY: this is a STRUCTURAL parse only. It does NOT verify the quote's
// signature or that it chains to a genuine Intel TDX root, so the values it
// returns are meaningful only once the quote's signature has been verified —
// that is the job of the real quote parser wired via WithQuoteParser (which
// calls this only after verifying). It deliberately returns a QuoteBody (not the
// quoteParser signature) so it cannot be mistaken for, or wired in as, a
// verifying parser. Never feed its output into a trust decision on its own.
func ParseTDXQuoteBody(raw []byte) (QuoteBody, error) {
	if len(raw) < minQuoteLen {
		return QuoteBody{}, fmt.Errorf("attest: quote too short: %d bytes, need >= %d", len(raw), minQuoteLen)
	}
	var b QuoteBody
	copy(b.Measurement.MRTD[:], raw[mrtdOff:mrtdOff+measurementRegLen])
	copy(b.Measurement.RTMR0[:], raw[rtmr0Off:rtmr0Off+measurementRegLen])
	copy(b.Measurement.RTMR1[:], raw[rtmr1Off:rtmr1Off+measurementRegLen])
	copy(b.Measurement.RTMR2[:], raw[rtmr2Off:rtmr2Off+measurementRegLen])
	copy(b.Measurement.RTMR3[:], raw[rtmr3Off:rtmr3Off+measurementRegLen])
	copy(b.ReportData[:], raw[reportDataOff:reportDataOff+reportDataLen])
	return b, nil
}
