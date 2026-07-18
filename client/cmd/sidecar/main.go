// Command sidecar is the local sidecar form: the client core wrapped as a
// localhost OpenAI-compatible proxy. Runs on the user's own machine (user-
// operated; no new trust party). Point any OpenAI SDK at it via base_url.
package main

func main() {
	// TODO: serve the OpenAI-compatible API on localhost, backed by client/core.
}
