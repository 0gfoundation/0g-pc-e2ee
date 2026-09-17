//go:build peakprofile

// Measures perRequestPeakFactor rather than reasoning about it.
//
// Run with:
//
//	go test -tags peakprofile ./cmd/gateway/ -run TestPerRequestPeakFactor -v -timeout 10m
//
// Behind a build tag because it is a MEASUREMENT, not an assertion: it takes
// minutes, it allocates gigabytes on purpose, and its output is a number a human
// reads. A test that failed on a threshold here would be a flaky test on every
// machine with a different GC schedule.
//
// WHAT THE CONSTANT CLAIMS. perRequestPeakBytes = perRequestPeakFactor ×
// MaxRequestBytes is "the peak memory one in-flight request can hold", and
// computeMaxInFlight divides half the process's memory limit by it. So the
// number to measure is peak LIVE heap attributable to one in-flight request at
// the body cap — not total allocation, which is a GC-pressure figure and much
// larger.
//
// WHY THE UPSTREAM HOLDS THE REQUEST. In production almost all of a request's
// in-flight time is the provider's inference, so "peak in-flight memory" is
// really "what is still reachable while waiting on the provider". An upstream
// that answered instantly would measure a transient nobody is concurrent with.
// The upstream here reads the body, holds for holdFor, and then fails — so K
// requests are genuinely simultaneous, which the run asserts rather than assumes
// (see maxConcurrent).
//
// WHY THE UPSTREAM DISCARDS. It runs in this process, so anything it retains
// lands in the same heap and cannot be told apart by sampling. A real provider's
// memory is on another machine. So it copies the body to io.Discard and keeps
// nothing: what is left in the delta is the gateway's.
//
// The consequence is that this measures the REQUEST path. That is where the
// base64 inflation lives, and a sealed speech response is a transcript — the
// response-side ceiling is maxDecompressedSize / maxImageResponseSize, separate
// constants with their own sizing.
//
// WHAT IT MEASURED (4 vCPU, Go 1.24, GOGC default, bodies at the 10 MiB cap).
// Two independent methods agree, which is the only reason to believe either:
//
//	peak live heap, no memory limit    speech 10.0-12.8x   chat 6.5-7.7x
//	footprint vs K under a 4 GiB limit 109-126 MiB/request = 10.9-12.6x
//
// Both are RANGES ACROSS RUNS, not one run's readings, because GC scheduling
// moves them by a MiB or two per request. Quoting a single run to two decimal
// places would be a precision this harness does not have; what it has is two
// methods that agree on the same order of magnitude.
//
// The footprint figure is the slope, taken where it is linear: K=1 and K=8
// (143-170 MiB and 932-1027 MiB), because K=34 and K=68 both pin at ~95% of the
// limit — past saturation the limit binds and the reading stops being about the
// requests. TestFootprintTracksConcurrency is what establishes where that line
// is, and without it the saturated rows read as a much worse result than they
// are.
//
// So perRequestPeakFactor = 3 understates the real cost by roughly 4x, and the
// speech surface is about 1.5x the chat one — the double base64 (+33% into the
// JSON-ified request, +33% again into the sealed envelope).
//
// K=1 alone reads higher (14-17x) because the fixed costs are not amortized over
// anything; the marginal figure is the one the constant wants.
//
// A FACTOR ALONE DOES NOT FIX IT. At 12x the arithmetic comes out right for
// limits of 4 GiB and up (K x ~120 MiB lands near half the limit, which is what
// memBudgetDivisor intends). Below that, minDefaultInFlight = 32 overrides the
// arithmetic entirely and promises 32 x ~120 MiB = 3.6 GiB of slots to a process
// limited to 1 GiB. And maxDefaultInFlight = 512, the bound that governs when no
// limit is set at all, is priced in its comment at 512 x 30 MiB = 15 GiB; at the
// measured cost it is 512 x 120 MiB = 61 GiB.
//
// That was checked rather than inferred: running the same limits priced at 6x
// moved the footprint barely at all, because the floor still governed. It is the
// reason this file reports a finding about the FLOOR alongside the one about the
// factor.
//
// Those are capacity decisions with availability consequences — lowering a bound
// refuses traffic the gateway serves today — so this file measures and does not
// change them.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

const (
	// holdFor is how long the upstream lingers AFTER the barrier releases, so the
	// sampler has a window in which all K are demonstrably simultaneous.
	holdFor = 300 * time.Millisecond
	// barrierTimeout stops a cell hanging when a request never arrives. It does
	// not rescue the cell — the overlap assertion reports it as invalid.
	barrierTimeout = 30 * time.Second
	// samplePeriod is the sampler's loop delay. runtime/metrics.Read is not
	// stop-the-world (unlike ReadMemStats), so this can be tight without
	// distorting what it measures.
	samplePeriod = 200 * time.Microsecond
)

// heapLive reads bytes in live heap objects. This is the quantity the constant
// is about: not total allocation, and not the process RSS (which includes heap
// Go has not returned to the OS).
func heapLive(sample []metrics.Sample) uint64 {
	metrics.Read(sample)
	return sample[0].Value.Uint64()
}

func newHeapSample() []metrics.Sample {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 {
		panic("heap objects metric unavailable")
	}
	return s
}

type peakResult struct {
	name          string
	concurrency   int
	bodyBytes     int
	maxConcurrent int64
	baseline      uint64
	peak          uint64
	factor        float64
}

func (r peakResult) String() string {
	return fmt.Sprintf("%-18s K=%-3d body=%5.1fMiB  overlap=%-3d  baseline=%6.1fMiB  peak=%7.1fMiB  factor=%.2fx",
		r.name, r.concurrency, float64(r.bodyBytes)/(1<<20), r.maxConcurrent,
		float64(r.baseline)/(1<<20), float64(r.peak)/(1<<20), r.factor)
}

// measurePeak runs one (surface, concurrency, body size) cell and returns the
// peak live heap per in-flight request, expressed as a multiple of the body
// size.
func measurePeak(t *testing.T, name string, ep endpoint.Endpoint, buildBody func(int) ([]byte, string), concurrency, bodyBytes int) peakResult {
	t.Helper()

	// The upstream is a BARRIER, not a delay. Holding each request for a fixed
	// time does not make K of them simultaneous: sealing a body at the cap is
	// CPU-bound, so on a 4-core box the requests arrive staggered and a fixed
	// hold expires on the early ones before the late ones show up. Measured — a
	// 300ms hold produced 16 of 32, then 54 of 68 overlapping, so those cells
	// reported a partial burst as a peak.
	//
	// So: every request waits until ALL of them have arrived, then they are held
	// together. K in flight in production means K simultaneously waiting on a
	// provider, and that is the worst case the constant has to cover.
	var inUpstream, maxConcurrent atomic.Int64
	allArrived := make(chan struct{})
	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and drop: whatever this process's upstream keeps would land in the
		// same heap as the gateway's and could not be separated by sampling.
		_, _ = io.Copy(io.Discard, r.Body)
		// Counted AFTER the read, so "arrived" means the gateway has finished
		// sealing and sending and is now waiting on the provider — the state the
		// measurement is about.
		n := inUpstream.Add(1)
		for {
			cur := maxConcurrent.Load()
			if n <= cur || maxConcurrent.CompareAndSwap(cur, n) {
				break
			}
		}
		if n >= int64(concurrency) {
			once.Do(func() { close(allArrived) })
		}
		select {
		case <-allArrived:
		case <-time.After(barrierTimeout):
			// A request that never arrives (a 413, a transport error) would
			// otherwise deadlock the rest. The overlap assertion is what reports
			// that the cell is invalid; this just stops it hanging.
		}
		time.Sleep(holdFor)
		inUpstream.Add(-1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":{"message":"held and dropped"}}`)
	}))
	defer upstream.Close()

	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc key: %v", err)
	}
	mux := http.NewServeMux()
	openaiproxy.Register(mux, ep, core.New(core.Provider{
		URL:        upstream.URL,
		EncPubKey:  encPub,
		SignerAddr: "0x000000000000000000000000000000000000dEaD",
	}, core.WithEndpoint(ep)))
	gw := httptest.NewServer(mux)
	defer gw.Close()

	// ONE shared body, K readers over it. Each reader is a few words; the
	// server-side io.ReadAll makes its own copy per request, which is the thing
	// being measured. Building K bodies instead would put K copies in the heap
	// before the measurement even started and count them twice.
	shared, contentType := buildBody(bodyBytes)

	client := &http.Client{Transport: &http.Transport{
		MaxIdleConns:        concurrency * 2,
		MaxIdleConnsPerHost: concurrency * 2,
	}}
	defer client.CloseIdleConnections()

	// Baseline with everything allocated and reachable EXCEPT the in-flight
	// requests: servers up, shared body built, client built.
	//
	// FreeOSMemory, not just GC: the footprint metric GOMEMLIMIT accounts for
	// subtracts only heap Go has RETURNED to the OS, so a plain GC leaves the
	// previous cell's arena counted. Measured — consecutive cells reported
	// baselines of 7MiB, 959MiB and 1963MiB, which made each peak mostly its
	// predecessor's garbage and every verdict meaningless.
	debug.FreeOSMemory()
	sample := newHeapSample()
	baseline := heapLive(sample)

	stop := make(chan struct{})
	peakCh := make(chan uint64, 1)
	go func() {
		local := newHeapSample()
		var peak uint64
		for {
			select {
			case <-stop:
				peakCh <- peak
				return
			default:
			}
			if live := heapLive(local); live > peak {
				peak = live
			}
			time.Sleep(samplePeriod)
		}
	}()

	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			resp, err := client.Post(gw.URL+ep.Path, contentType, bytes.NewReader(shared))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	close(release)
	wg.Wait()
	close(stop)
	peak := <-peakCh

	// The shared body is in both baseline and peak, so it cancels. What remains
	// is K requests' worth.
	var factor float64
	if peak > baseline {
		factor = float64(peak-baseline) / float64(concurrency) / float64(bodyBytes)
	}
	return peakResult{
		name: name, concurrency: concurrency, bodyBytes: bodyBytes,
		maxConcurrent: maxConcurrent.Load(),
		baseline:      baseline, peak: peak, factor: factor,
	}
}

// fitToSize builds a body whose TOTAL length is at most target, by measuring the
// shape's fixed overhead once and re-building the payload that much smaller.
//
// It exists because getting this wrong silently invalidates a cell: the size
// knob is the payload, the cap is on the whole BODY, and a payload sized at the
// cap makes a body just over it. MaxBytesReader then answers 413 before anything
// is decoded or sealed, so the cell measures the reject path — which is why the
// run asserts every request reached the upstream. The first version of this file
// did exactly that in five of seven cells.
func fitToSize(target int, build func(payload int) ([]byte, string)) ([]byte, string) {
	body, ct := build(target)
	if overhead := len(body) - target; overhead > 0 {
		body, ct = build(target - overhead)
	}
	if len(body) > target {
		panic(fmt.Sprintf("fitToSize: body is %d bytes, target %d", len(body), target))
	}
	return body, ct
}

// speechBody builds a multipart transcription request of about n TOTAL bytes —
// the shape every OpenAI SDK posts, and the one that pays base64's +33% twice
// (once into the JSON-ified request, once into the sealed envelope).
func speechBody(n int) ([]byte, string) {
	return fitToSize(n, func(audioBytes int) ([]byte, string) {
		if audioBytes < 1 {
			audioBytes = 1
		}
		audio := bytes.Repeat([]byte{0x41, 0xf0, 0x9f}, audioBytes/3+1)[:audioBytes]
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		fw, err := w.CreateFormFile("file", "load.m4a")
		if err != nil {
			panic(err)
		}
		if _, err := fw.Write(audio); err != nil {
			panic(err)
		}
		if err := w.WriteField("model", "mock-model"); err != nil {
			panic(err)
		}
		if err := w.Close(); err != nil {
			panic(err)
		}
		return buf.Bytes(), w.FormDataContentType()
	})
}

// chatBody builds a JSON chat request of about n TOTAL bytes, for the comparison
// that decides whether speech is the new worst case. Its payload is sealed but
// never base64'd on the way IN, so the same body should cost less.
func chatBody(n int) ([]byte, string) {
	return fitToSize(n, func(promptBytes int) ([]byte, string) {
		if promptBytes < 1 {
			promptBytes = 1
		}
		filler := bytes.Repeat([]byte("lorem ipsum dolor sit amet "), promptBytes/27+1)[:promptBytes]
		body, err := json.Marshal(map[string]any{
			"model":    "mock-model",
			"messages": []any{map[string]string{"role": "user", "content": string(filler)}},
		})
		if err != nil {
			panic(err)
		}
		return body, "application/json"
	})
}

func TestPerRequestPeakFactor(t *testing.T) {
	const MiB = 1 << 20
	// The cap itself, less a margin: MaxBytesReader errors on reading MORE than
	// the limit, and a cell that trips it measures the reject path.
	atCap := openaiproxy.MaxRequestBytes - 4096
	cells := []struct {
		name        string
		ep          endpoint.Endpoint
		build       func(int) ([]byte, string)
		concurrency int
		bodyBytes   int
	}{
		// Linearity first: if the factor is a property of the shape rather than of
		// the size, these three agree and the constant can stay a multiple.
		{"speech", endpoint.Speech, speechBody, 8, 1 * MiB},
		{"speech", endpoint.Speech, speechBody, 8, 4 * MiB},
		{"speech", endpoint.Speech, speechBody, 8, atCap},
		// Then concurrency: the factor is per-request, so it should not move.
		{"speech", endpoint.Speech, speechBody, 1, atCap},
		{"speech", endpoint.Speech, speechBody, 32, atCap},
		// And the comparison the shared constant actually turns on.
		{"chat", endpoint.Chat, chatBody, 8, atCap},
		{"chat", endpoint.Chat, chatBody, 32, atCap},
	}

	results := make([]peakResult, 0, len(cells))
	for _, c := range cells {
		r := measurePeak(t, c.name, c.ep, c.build, c.concurrency, c.bodyBytes)
		t.Log(r)
		results = append(results, r)
		// Give the next cell a clean start rather than its predecessor's garbage.
		runtime.GC()
	}

	t.Log("")
	t.Logf("perRequestPeakFactor is currently %d, priced against MaxRequestBytes = %d MiB",
		perRequestPeakFactor, MaxRequestBytesMiB())
	worst := 0.0
	for _, r := range results {
		if r.factor > worst {
			worst = r.factor
		}
		if r.maxConcurrent < int64(r.concurrency) {
			t.Errorf("%s: only %d of %d requests overlapped; the cell measured a transient, not a peak",
				r.name, r.maxConcurrent, r.concurrency)
		}
	}
	t.Logf("worst measured factor: %.2fx", worst)
}

// MaxRequestBytesMiB keeps the log line honest if the cap ever moves.
func MaxRequestBytesMiB() int { return openaiproxy.MaxRequestBytes / (1 << 20) }

// runtimeFootprint is the quantity GOMEMLIMIT actually accounts for: the Go
// runtime's total mapped memory less what it has returned to the OS. The heap
// figure above is a component of it and NOT what the limit governs, which is
// why this test reads a different metric than the last one.
func runtimeFootprint(sample []metrics.Sample) uint64 {
	metrics.Read(sample)
	return sample[0].Value.Uint64() - sample[1].Value.Uint64()
}

func newFootprintSample() []metrics.Sample {
	s := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(s)
	for i := range s {
		if s[i].Value.Kind() != metrics.KindUint64 {
			panic("footprint metric unavailable: " + s[i].Name)
		}
	}
	return s
}

func gcCPUFraction(sample []metrics.Sample) float64 {
	metrics.Read(sample)
	return sample[0].Value.Float64()
}

func newGCCPUSample() []metrics.Sample {
	s := []metrics.Sample{{Name: "/cpu/classes/gc/total:cpu-seconds"}}
	metrics.Read(s)
	return s
}

// TestMemoryLimitHolds runs the constant's own arithmetic against real memory
// limits: computeMaxInFlight divides half the limit by perRequestPeakBytes, so
// the claim is "K concurrent requests at the body cap fit inside half of L".
//
// READ THIS WITH TestFootprintTracksConcurrency, not on its own. Every row here
// reports 95-100% of the limit for every factor, which looks like a damning
// verdict and is mostly an artifact: at these limits the rows are at or past
// SATURATION, where the limit binds and the footprint pins to it whatever K is.
// The control below sweeps K at one limit and finds the footprint linear in K
// until it saturates — so the useful figure comes from the unsaturated rows
// there, and the rows here only show WHERE saturation starts.
//
// The gcCPU column is not trustworthy in this harness and is printed for shape
// only: its denominator is wall time, which includes the barrier wait where
// nothing allocates, so cells with different arrival spreads are not comparable.
// Treat a double-digit figure as "worth measuring properly", not as a number.
//
// candidateFactors runs the same limits against a hypothetical factor. Note what
// that showed: raising the factor from 3 to 6 changed the footprint barely at
// all, because minDefaultInFlight floors K at 32 and the factor stops mattering
// below a 4 GiB limit. That is a finding about the FLOOR, not about the factor.
func TestMemoryLimitHolds(t *testing.T) {
	restore := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(restore) })

	atCap := openaiproxy.MaxRequestBytes - 4096
	for _, factor := range []int{perRequestPeakFactor, 6} {
		t.Logf("--- pricing a request at %dx MaxRequestBytes (%d MiB) ---",
			factor, factor*openaiproxy.MaxRequestBytes/(1<<20))
		for _, limitMiB := range []int{1024, 2048, 4096} {
			limit := int64(limitMiB) << 20
			debug.SetMemoryLimit(limit)

			// computeMaxInFlight's arithmetic, with the factor under test
			// substituted. Re-derived rather than called, because the constant is
			// what is being questioned — and the floor is re-applied because it is
			// part of the answer (see the 1 GiB row).
			perRequest := int64(factor) * int64(openaiproxy.MaxRequestBytes)
			k := int(limit / memBudgetDivisor / perRequest)
			floored := false
			if k < minDefaultInFlight {
				k, floored = minDefaultInFlight, true
			}
			if cpuTerm := inFlightPerCPU * runtime.GOMAXPROCS(0); k > cpuTerm {
				k = cpuTerm
			}
			if k > maxDefaultInFlight {
				k = maxDefaultInFlight
			}

			debug.FreeOSMemory()
			fp := newFootprintSample()
			gcs := newGCCPUSample()
			_ = runtimeFootprint(fp) // settle the sample struct before the burst
			gcBefore := gcCPUFraction(gcs)
			wall := time.Now()

			r := measurePeak(t, "speech", endpoint.Speech, speechBody, k, atCap)

			peakFp := runtimeFootprint(fp)
			gcSeconds := gcCPUFraction(gcs) - gcBefore
			elapsed := time.Since(wall)
			gcPct := 100 * gcSeconds / (elapsed.Seconds() * float64(runtime.GOMAXPROCS(0)))

			// The budget the constant promised to stay inside, and what it used.
			budget := float64(limit) / memBudgetDivisor
			verdict := "within budget"
			if peakFp > uint64(limit) {
				verdict = "EXCEEDED THE LIMIT"
			} else if float64(peakFp) > budget {
				verdict = "OVER BUDGET (held only by GC)"
			}
			note := ""
			if floored {
				note = fmt.Sprintf("  [K came from minDefaultInFlight=%d, not the arithmetic]", minDefaultInFlight)
			}
			t.Logf("  L=%-5dMiB K=%-3d  budget=%5.0fMiB  peak=%5.0fMiB (%.0f%% of L)  %-30s gcCPU=%4.1f%%%s",
				limitMiB, k, budget/(1<<20), float64(peakFp)/(1<<20),
				100*float64(peakFp)/float64(limit), verdict, gcPct, note)
			if r.maxConcurrent < int64(k) {
				t.Errorf("only %d of %d overlapped; the cell measured a transient", r.maxConcurrent, k)
			}
			debug.FreeOSMemory()
		}
	}
}

// TestFootprintTracksConcurrency is the control for the test above, and it is
// the one that decides whether that test measures anything.
//
// TestMemoryLimitHolds reported the footprint sitting at 95-100% of the memory
// limit for EVERY factor and every K — including K=34 and K=68 at the same
// limit, where halving the concurrency should have halved the memory if the
// footprint tracked the requests. That pattern has two possible causes and they
// call for opposite conclusions:
//
//   - the requests really do cost that much, and the constant badly
//     under-provisions; or
//   - a soft memory limit makes Go MAP memory freely up to the limit and collect
//     harder only as it approaches, so "total minus released" converges on the
//     limit regardless of demand — in which case the metric measures the
//     runtime's appetite, not the request's cost, and the whole test is void.
//
// Sweeping K against ONE limit separates them. If the footprint is flat across
// K, it is the second, and nothing in that test may be read as evidence about
// the factor.
func TestFootprintTracksConcurrency(t *testing.T) {
	restore := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(restore) })

	const limitMiB = 4096
	limit := int64(limitMiB) << 20
	debug.SetMemoryLimit(limit)
	atCap := openaiproxy.MaxRequestBytes - 4096

	for _, k := range []int{1, 8, 34, 68} {
		debug.FreeOSMemory()
		fp := newFootprintSample()
		gcs := newGCCPUSample()
		gcBefore := gcCPUFraction(gcs)
		wall := time.Now()

		r := measurePeak(t, "speech", endpoint.Speech, speechBody, k, atCap)

		peakFp := runtimeFootprint(fp)
		gcPct := 100 * (gcCPUFraction(gcs) - gcBefore) /
			(time.Since(wall).Seconds() * float64(runtime.GOMAXPROCS(0)))
		t.Logf("  L=%dMiB K=%-3d  footprint peak=%5.0fMiB (%3.0f%% of L)  heap peak=%5.0fMiB  gcCPU=%4.1f%%",
			limitMiB, k, float64(peakFp)/(1<<20), 100*float64(peakFp)/float64(limit),
			float64(r.peak)/(1<<20), gcPct)
		if r.maxConcurrent < int64(k) {
			t.Errorf("only %d of %d overlapped; the cell measured a transient", r.maxConcurrent, k)
		}
		debug.FreeOSMemory()
	}
}
