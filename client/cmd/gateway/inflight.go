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

	// maxDefaultInFlight bounds the default no matter how many cores appear. At
	// openaiproxy.MaxRequestBytes per buffered body this is ~10 GiB of worst-case
	// request buffer, which a 32 GiB CVM survives with room for GC headroom, the
	// response side, and its sibling containers. It bounds only the DEFAULT — an
	// explicit -max-inflight is honored as given, because an operator naming a
	// number has context this arithmetic does not.
	maxDefaultInFlight = 1024

	// minDefaultInFlight floors the memory-derived term. A small GOMEMLIMIT must
	// not shrink the gateway to a handful of slots, which would be a self-inflicted
	// outage dressed up as protection.
	minDefaultInFlight = 32

	// perRequestPeakFactor multiplies MaxRequestBytes to estimate the peak memory
	// one in-flight request can hold: the buffered body, plus the parsed copy, plus
	// the sealed and base64'd envelope built from it. Approximate by nature —
	// it is a budgeting input, not an accounting one.
	perRequestPeakFactor = 3

	// memBudgetDivisor is the share of GOMEMLIMIT the request bodies may claim.
	// Half, because the other half is the response side, the quote/collateral
	// caches, and the headroom Go's collector needs to not thrash.
	memBudgetDivisor = 2
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
		perRequest := int64(perRequestPeakFactor) * int64(openaiproxy.MaxRequestBytes)
		fromMem := int(memLimit / memBudgetDivisor / perRequest)
		if fromMem < minDefaultInFlight {
			fromMem = minDefaultInFlight
		}
		if fromMem < n {
			n = fromMem
		}
	}
	return n
}
