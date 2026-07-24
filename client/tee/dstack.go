package tee

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

// DefaultDstackSocket is the tappd unix socket dstack exposes inside the CVM.
const DefaultDstackSocket = "/var/run/dstack.sock"

// maxTappdResponse caps the tappd reply we read. A quote is a few KiB; this
// bounds a misbehaving socket without truncating any real response.
const maxTappdResponse = 4 << 20 // 4 MiB

// Dstack is the in-enclave Attestor: it calls the dstack tappd socket over HTTP,
// mirroring the broker's proven PhalaTappdClient (api/common/tee/phala.go). It
// deliberately uses the raw RPC rather than the dstack SDK so the gateway pulls
// no extra dependency for the one call it needs.
type Dstack struct {
	// Socket is the tappd unix socket path; empty uses DefaultDstackSocket.
	Socket string
}

func (d *Dstack) socket() string {
	if d.Socket == "" {
		return DefaultDstackSocket
	}
	return d.Socket
}

// httpClient dials the unix socket regardless of the URL host, so a normal
// http://localhost URL is transported over the socket.
func (d *Dstack) httpClient() *http.Client {
	sock := d.socket()
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}
}

func (d *Dstack) Quote(ctx context.Context, reportData []byte) (*Quote, error) {
	if len(reportData) > MaxReportData {
		return nil, fmt.Errorf("report_data is %d bytes, must be at most %d", len(reportData), MaxReportData)
	}

	payload, err := json.Marshal(map[string]string{
		"report_data": hex.EncodeToString(reportData),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal report_data: %w", err)
	}
	client := d.httpClient()

	var quoteResp struct {
		Quote    string `json:"quote"`
		EventLog string `json:"event_log"`
		VmConfig string `json:"vm_config"`
		TcbInfo  string `json:"tcb_info"`
	}
	if err := d.rpc(ctx, client, "/GetQuote", payload, &quoteResp); err != nil {
		return nil, fmt.Errorf("GetQuote: %w", err)
	}
	// A 200 with an empty quote (schema drift, an error envelope in an unexpected
	// shape, a partial body) must not be reported as success — otherwise the
	// caller caches and serves an attestation that binds nothing. Fail so it hits
	// the uncached retry path instead.
	if quoteResp.Quote == "" {
		return nil, fmt.Errorf("GetQuote: tappd returned an empty quote")
	}

	// /Info carries tcb_info separately on some dstack versions; a failure here is
	// non-fatal — the quote is still valid, tcb_info just aids TCB-status checks —
	// but log it so a persistently-missing tcb_info is diagnosable.
	if quoteResp.TcbInfo == "" {
		var info struct {
			TcbInfo string `json:"tcb_info"`
		}
		if err := d.rpc(ctx, client, "/Info", payload, &info); err == nil {
			quoteResp.TcbInfo = info.TcbInfo
		} else {
			log.Printf("attestation: /Info tcb_info unavailable (non-fatal): %v", err)
		}
	}

	return &Quote{
		Quote:      quoteResp.Quote,
		EventLog:   quoteResp.EventLog,
		ReportData: reportData,
		VmConfig:   quoteResp.VmConfig,
		TcbInfo:    quoteResp.TcbInfo,
	}, nil
}

// rpc POSTs payload to path on the tappd socket and decodes the JSON reply into
// out.
func (d *Dstack) rpc(ctx context.Context, client *http.Client, path string, payload []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTappdResponse))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tappd returned %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
