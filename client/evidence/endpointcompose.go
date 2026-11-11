package evidence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// EndpointAppComposePath is where the cloud gateway serves its own app-compose.json
// (client/cmd/gateway appComposeHandler).
const EndpointAppComposePath = "/v1/gateway/app-compose"

// ErrEndpointServesNoAppCompose is a 404 from EndpointAppComposePath: the endpoint
// does not publish its manifest (an older gateway, or not a gateway at all). It is
// an absence, not a failed lookup, and is reported as such.
var ErrEndpointServesNoAppCompose = errors.New("the endpoint does not serve " + EndpointAppComposePath)

// maxEndpointAppComposeBytes bounds the read. A gateway's app-compose is a few KiB;
// a megabyte is room for any real one and a ceiling on a hostile answer.
const maxEndpointAppComposeBytes = 1 << 20

// FetchAppComposeFromEndpoint reads the raw app-compose bytes from the endpoint
// being verified: GET https://<domain>/v1/gateway/app-compose.
//
// Why ask the endpoint. The two platform paths — Phala Cloud's attestations API
// and the CVM's guest agent — both stopped answering anonymous callers, which left
// code identity unestablished for every deployment. The endpoint has the bytes
// (cmd/cvmid publishes them to it) and needs nothing from the platform to serve
// them.
//
// Why that does not make the endpoint trusted: nothing here is believed. The
// caller gates the bytes on the compose_hash of the DCAP-verified quote
// (VerifyAppCompose), exactly as it does the platform's answers; a gateway that
// serves anything else is caught by that check, not by this function. The usual
// rules for a fetched file apply on top: a non-200 is an error rather than bytes
// to hash, and the read is bounded.
//
// It returns the bytes and the URL they came from, for the report.
//
// host is the endpoint's authority as dialled (hostname, optionally with a port);
// hc is normally the run's pinned session, so the request rides the connection
// whose certificate step 4 bound to the quote.
func FetchAppComposeFromEndpoint(ctx context.Context, hc *http.Client, host string) ([]byte, string, error) {
	u := "https://" + host + EndpointAppComposePath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, u, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, u, fmt.Errorf("fetch app-compose from %s: %w", u, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEndpointAppComposeBytes+1))
	if err != nil {
		return nil, u, fmt.Errorf("read app-compose from %s: %w", u, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, u, ErrEndpointServesNoAppCompose
	}
	if resp.StatusCode != http.StatusOK {
		return nil, u, fmt.Errorf("GET %s -> %s", u, resp.Status)
	}
	if len(body) > maxEndpointAppComposeBytes {
		return nil, u, fmt.Errorf("app-compose from %s is larger than %d bytes", u, maxEndpointAppComposeBytes)
	}
	return body, u, nil
}
