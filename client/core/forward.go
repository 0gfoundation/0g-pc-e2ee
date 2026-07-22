package core

import (
	"context"
	"net/http"
)

// forwardHeadersKey is the unexported context key under which additional
// request headers to forward to the provider travel.
type forwardHeadersKey struct{}

// WithForwardedHeaders returns a context carrying request headers to copy
// verbatim onto the provider request — the cleartext routing directives the
// router consumes (the X-0G-* namespace: provider pin, sort strategy, trust
// mode, fallbacks, require-parameters). They are routing metadata, not
// confidential: the router must read them to route, so they ride cleartext
// alongside model/sampling, never the sealed fields.
//
// A nil/empty header is a no-op. The credential (WithCredential) is applied
// after these, so a forwarded header can never clobber the Authorization the
// caller presented.
func WithForwardedHeaders(ctx context.Context, h http.Header) context.Context {
	if len(h) == 0 {
		return ctx
	}
	// Clone so a later mutation of the caller's map cannot alter what we send.
	return context.WithValue(ctx, forwardHeadersKey{}, h.Clone())
}

// ForwardedHeadersFrom returns the headers carried by ctx, or nil if none. It
// is exported so a Resolver (route mode) can forward the same X-0G-* routing
// directives on its control-plane call to the router. The context key stays
// unexported, so only WithForwardedHeaders can set it.
func ForwardedHeadersFrom(ctx context.Context) http.Header {
	h, _ := ctx.Value(forwardHeadersKey{}).(http.Header)
	return h
}
