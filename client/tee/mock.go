package tee

import (
	"context"
	"encoding/hex"
	"fmt"
)

// Mock is a non-TEE Attestor for local development and tests. It returns a
// deterministic, clearly-fake quote that echoes the report_data, so the /quote
// endpoint and its wiring can be exercised without a real enclave. It provides
// NO security — a downloader verifying the quote MUST reject it.
type Mock struct{}

func (Mock) Quote(_ context.Context, reportData []byte) (*Quote, error) {
	if len(reportData) > MaxReportData {
		return nil, fmt.Errorf("report_data is %d bytes, must be at most %d", len(reportData), MaxReportData)
	}
	return &Quote{
		Quote:      "mock-quote:" + hex.EncodeToString(reportData),
		EventLog:   "mock-event-log",
		ReportData: reportData,
		TcbInfo:    `{"mock":"tcb_info"}`,
	}, nil
}
