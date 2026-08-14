package main

import (
	"math"
	"runtime"
	"runtime/debug"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// The built-in concurrency ceiling, and the arithmetic behind it.
//
// Concurrency costs two different resources, and they do not scale together.
//
// CPU is the one the cap was originally reasoned about: sealing a request and
// opening each response frame is real HPKE work, so a bigger CVM can carry
// proportionally more in flight. Hence a per-CPU term.
//
// MEMORY does not follow the core count at all, and it is the axis that can kill
// the process rather than merely slow it. A request body is read FULLY into
// memory (openaiproxy.MaxRequestBytes, 10 MiB) before anything else happens, and
// then parsed and sealed on top of that. So the worst case is not "slower" — it
// is the OOM killer taking the whole gateway, and with it every user on it. That
// is precisely the outcome this cap exists to prevent, so a cap high enough to
// permit it is not doing its job.
//
// A purely per-CPU default crosses that line on a large CVM: at 256/CPU, a
// 16-vCPU box defaults to 4096, whose worst-case buffered bodies alone are
// 4096 x 10 MiB = 40 GiB — more than such a box typically has, and it is shared
// with dstack-ingress and the metrics agent besides. Reaching it needs no
// cleverness, just concurrent large POSTs. So the default is bounded on both
// axes and takes the smaller.
//
// Two things this deliberately does NOT do. It does not read the cgroup memory
// limit (platform-specific, and inside a CVM the guest's own view is the honest
// one); it uses GOMEMLIMIT when the operator has set it, which is the only case
// where the budget is actually known. And it does not try to be the right
// number — it tries to be a safe one. An L3 run (in-CVM, behind dstack-ingress)
// produces the real knee, and the deployment should then set
// ZG_GATEWAY_MAX_INFLIGHT explicitly rather than inherit any of this.
const (
	// inFlightPerCPU is the per-CPU term. Generous on purpose: a streamed
	// completion is held for its whole token schedule, so healthy in-flight
	// counts sit far above the arrival rate, and a cap near the knee would refuse
	// traffic the gateway is still serving fine.
	inFlightPerCPU = 256

	// maxDefaultInFlight bounds the default no matter how many cores appear. Priced
	// with perRequestPeakBytes below — the SAME model as the GOMEMLIMIT term, which
	// is the whole point: an earlier revision priced this bound at 1x
	// MaxRequestBytes and the other at 3x, so the file disagreed with itself about
	// what a request costs and the looser number won on every deployment that had
	// no GOMEMLIMIT set. At 512 the worst case is 512 x 30 MiB = 15 GiB.
	//
	// This is the bound that matters MOST, because it is the one that applies when
	// nothing else is configured — a deployment outside the Phala CVM (local, a
	// future GCP/AWS host) has no GOMEMLIMIT and lands here. The unconfigured path
	// is exactly the OOM this cap exists to prevent, so it is the last place to be
	// generous.
	//
	// It bounds only the DEFAULT — an explicit -max-inflight is honored as given,
	// because an operator naming a number has context this arithmetic does not.
	//
	// Note this leaves the per-CPU term above binding only on a single-core host
	// (256), since 2 cores already reach 512. That is the honest outcome of pricing
	// both bounds the same way: past one core, memory is what limits concurrency,
	// not CPU.
	maxDefaultInFlight = 512

	// minDefaultInFlight floors the memory-derived term. A small GOMEMLIMIT must
	// not shrink the gateway to a handful of slots, which would be a self-inflicted
	// outage dressed up as protection.
	minDefaultInFlight = 32

	// perRequestPeakFactor multiplies MaxRequestBytes to estimate the peak memory
	// one in-flight request can hold: the buffered body, plus the parsed copy, plus
	// the sealed and base64'd envelope built from it. Approximate by nature —
	// it is a budgeting input, not an accounting one.
	//
	// EVERY memory bound in this file must be priced with it. Two bounds using two
	// different factors is not a conservative belt-and-braces arrangement; it is a
	// file that disagrees with itself, where the looser number silently governs.
	perRequestPeakFactor = 3

	// memBudgetDivisor is the share of GOMEMLIMIT the request bodies may claim.
	// Half, because the other half is the response side, the quote/collateral
	// caches, and the headroom Go's collector needs to not thrash.
	memBudgetDivisor = 2

	// perRequestPeakBytes is the one place the per-request memory price is
	// expressed. Both bounds and the test read it, so neither can be re-derived
	// with a different factor by accident.
	perRequestPeakBytes = perRequestPeakFactor * openaiproxy.MaxRequestBytes
)

// defaultMaxInFlight is the built-in ceiling for this process: the per-CPU term,
// bounded by the absolute cap, and further bounded by the GOMEMLIMIT-derived
// budget when a limit is set.
func defaultMaxInFlight() int {
	return computeMaxInFlight(runtime.GOMAXPROCS(0), currentMemoryLimit())
}

// currentMemoryLimit reports the process's soft memory limit, or
// math.MaxInt64 when none is set (which is Go's own representation of
// "unlimited"). Passing -1 reads the limit without changing it.
func currentMemoryLimit() int64 { return debug.SetMemoryLimit(-1) }

// computeMaxInFlight is the pure form, so the arithmetic can be asserted without
// touching process-global state. memLimit is math.MaxInt64 when unset.
func computeMaxInFlight(cpus int, memLimit int64) int {
	if cpus < 1 {
		cpus = 1
	}
	n := inFlightPerCPU * cpus
	if n > maxDefaultInFlight {
		n = maxDefaultInFlight
	}
	// Only meaningful when a limit is actually set; unset reads as MaxInt64 and
	// the division would overflow into a no-op anyway.
	if memLimit > 0 && memLimit < math.MaxInt64 {
		fromMem := int(memLimit / memBudgetDivisor / int64(perRequestPeakBytes))
		if fromMem < minDefaultInFlight {
			fromMem = minDefaultInFlight
		}
		if fromMem < n {
			n = fromMem
		}
	}
	return n
}
