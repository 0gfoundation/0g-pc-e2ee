package route

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
)

// metricValue scrapes the process registry and returns one series' value, or 0
// when it has not been emitted. Counters here are process-global, so a test reads
// a DELTA around the call under test rather than an absolute — otherwise it would
// depend on which other tests ran first.
func metricValue(t *testing.T, series string) float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if !strings.HasPrefix(line, series+" ") {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, series)), 64)
		if err != nil {
			t.Fatalf("parsing %q: %v", line, err)
		}
		return v
	}
	return 0
}
