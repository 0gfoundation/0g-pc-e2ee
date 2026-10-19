package route

// untrusted.go is the line between parsing what a provider wrote and this process
// staying up.
//
// Since the sealing path judges what a provider runs (runtimerelease.go) and what it
// booted (composebaseline.go), the gateway and the sidecar parse two things a provider
// controls: the event log in its quote reply and the manifest its compose hash commits
// to. Both are parsed inside the quote singleflight, which re-panics on its caller's
// goroutine, so a panic in either parser would take down a process that serves every
// other provider too — and, with the quote never cached, again on the next miss. The
// parsers guard themselves (evidence/compose's reviewFields, its loadModel); these
// guards are the boundary that does not depend on that: whatever a parser does with the
// input, a panic here becomes a check that did not run on that one provider, logged with
// its stack so it can be fixed.

import (
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence/compose"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// errReaderFailed marks a provider's input this process failed to read: never a finding
// against the provider, always unavailable.
var errReaderFailed = errors.New("this process failed while reading it")

// The parsers, as variables only so a test can make them fail the way no input is known
// to.
var (
	reviewCompose    = compose.ReviewCompose
	readRuntimeState = evidence.ReadRuntimeState
)

// reviewManifest is compose.ReviewCompose behind the boundary.
func (r *Router) reviewManifest(appCompose []byte, composeHash [attest.ComposeHashLen]byte,
	quoteURL string) (review compose.ComposeReview, err error) {
	defer r.recoverReader("manifest", quoteURL, &err)
	return reviewCompose(appCompose, composeHash, nil)
}

// readRuntime is evidence.ReadRuntimeState behind the boundary.
func (r *Router) readRuntime(reply []byte, rtmr3 [evidence.RTMRLen]byte, quoteURL string) (st evidence.RuntimeState,
	err error) {
	defer r.recoverReader("event log", quoteURL, &err)
	return readRuntimeState(reply, rtmr3)
}

// recoverReader turns a panic in a reader into errReaderFailed, logging it with its stack.
// Deferred directly, so recover sees the reader's panic.
func (r *Router) recoverReader(what, quoteURL string, err *error) {
	p := recover()
	if p == nil {
		return
	}
	*err = fmt.Errorf("the provider's %s was not read: %w (%v)", what, errReaderFailed, p)
	r.logger.Error("a reader of provider input panicked; the check did not run for this provider (a bug to fix, not a "+
		"finding)", "what", what, "quote_url", quoteURL, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
}
