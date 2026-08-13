package main

import (
	"math"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

const noMemLimit = int64(math.MaxInt64)

// TestComputeMaxInFlight_CPUTerm covers the axis the cap was first reasoned
// about: with no memory limit set, the default scales with the cores available.
func TestComputeMaxInFlight_CPUTerm(t *testing.T) {
	for _, tc := range []struct{ cpus, want int }{
		{1, 256},
		// 2 cores already reach the memory ceiling, so this is the last point at
		// which the per-CPU term is what decides. Above it, memory governs — see
		// maxDefaultInFlight.
		{2, 512},
	} {
		if got := computeMaxInFlight(tc.cpus, noMemLimit); got != tc.want {
			t.Errorf("computeMaxInFlight(%d, unset) = %d, want %d", tc.cpus, got, tc.want)
		}
	}
}

// TestComputeMaxInFlight_AbsoluteCeiling is the finding this function exists for:
// a purely per-CPU default crosses into OOM territory on a large CVM. At 256/CPU
// a 16-vCPU box would default to 4096, whose worst-case buffered bodies exceed
// the RAM such a box has. The default must stop scaling before then.
func TestComputeMaxInFlight_AbsoluteCeiling(t *testing.T) {
	for _, cpus := range []int{4, 8, 16, 32, 96} {
		got := computeMaxInFlight(cpus, noMemLimit)
		if got != maxDefaultInFlight {
			t.Errorf("computeMaxInFlight(%d, unset) = %d, want the ceiling %d — the default must not "+
				"scale with cores past the point where worst-case request memory exceeds RAM",
				cpus, got, maxDefaultInFlight)
		}
	}

	// The consequence in bytes, priced with perRequestPeakBytes — the SAME model
	// the GOMEMLIMIT term uses. An earlier version of this assertion priced it at
	// 1x MaxRequestBytes, which let a 30 GiB ceiling pass a 16 GiB threshold; the
	// bound and its test agreed with each other and disagreed with the rest of the
	// file. Anything that raises maxDefaultInFlight or MaxRequestBytes now has to
	// confront this number.
	//
	// The threshold is what an unconfigured deployment must survive — no
	// GOMEMLIMIT, so this ceiling is the only bound in play, and the host is
	// whatever someone happened to run it on.
	const maxWorstCaseBytes = 16 << 30
	worstCase := int64(maxDefaultInFlight) * int64(perRequestPeakBytes)
	if worstCase > maxWorstCaseBytes {
		t.Errorf("the ceiling permits %d GiB of concurrent request memory (%d slots x %d MiB peak), "+
			"over the %d GiB an unconfigured deployment must survive; lower maxDefaultInFlight "+
			"or openaiproxy.MaxRequestBytes",
			worstCase>>30, maxDefaultInFlight, perRequestPeakBytes>>20, maxWorstCaseBytes>>30)
	}
}

// TestComputeMaxInFlight_MemoryTermBinds confirms that when GOMEMLIMIT IS set,
// it can bind tighter than the CPU term — the case where the budget is actually
// known rather than assumed.
func TestComputeMaxInFlight_MemoryTermBinds(t *testing.T) {
	// 2 GiB limit → 1 GiB for bodies → at 30 MiB peak per request, ~34 slots.
	const limit = int64(2) << 30
	got := computeMaxInFlight(16, limit)

	perRequest := int64(perRequestPeakFactor) * int64(openaiproxy.MaxRequestBytes)
	want := int(limit / memBudgetDivisor / perRequest)
	if got != want {
		t.Errorf("computeMaxInFlight(16, 2GiB) = %d, want %d — a set memory limit must bind "+
			"tighter than the CPU term when it is smaller", got, want)
	}
	if got >= maxDefaultInFlight {
		t.Errorf("memory-derived default %d did not bind below the ceiling %d", got, maxDefaultInFlight)
	}
}

// TestComputeMaxInFlight_MemoryTermIsFloored keeps the protection from becoming
// the outage: a tiny GOMEMLIMIT must not shrink the gateway to a few slots.
func TestComputeMaxInFlight_MemoryTermIsFloored(t *testing.T) {
	if got := computeMaxInFlight(16, 64<<20); got != minDefaultInFlight {
		t.Errorf("computeMaxInFlight(16, 64MiB) = %d, want the floor %d — a small limit must not "+
			"self-DoS the gateway", got, minDefaultInFlight)
	}
}

// TestComputeMaxInFlight_DegenerateInputs pins the edges: GOMAXPROCS can never
// sensibly be < 1, and an unset/zero memory limit must not divide by anything.
func TestComputeMaxInFlight_DegenerateInputs(t *testing.T) {
	if got := computeMaxInFlight(0, noMemLimit); got != inFlightPerCPU {
		t.Errorf("computeMaxInFlight(0, unset) = %d, want %d (treated as one CPU)", got, inFlightPerCPU)
	}
	if got := computeMaxInFlight(2, 0); got != 512 {
		t.Errorf("computeMaxInFlight(2, 0) = %d, want 512 — a zero limit means unset, not zero budget", got)
	}
}

// TestDefaultMaxInFlight_IsUsable guards the wiring: whatever this process's real
// CPU and memory settings are, the built-in default must be a positive number the
// limiter can use (0 would silently disable the cap).
func TestDefaultMaxInFlight_IsUsable(t *testing.T) {
	if got := defaultMaxInFlight(); got < minDefaultInFlight || got > maxDefaultInFlight {
		t.Errorf("defaultMaxInFlight() = %d, want within [%d, %d]", got, minDefaultInFlight, maxDefaultInFlight)
	}
}
