// Command gateway is the cloud-TEE gateway form: the SAME client core wrapped
// as a server, but SERVER-RUN and 0G-operated — it runs inside an attested CVM
// and adds one attested trust party. Serves no-install / browser / thin clients
// that cannot run a sidecar. Clients MUST verify its quote and seal to it;
// running it without attestation degrades to today's plaintext L7 router.
package main

func main() {
	// TODO: serve the attested gateway (RA-TLS / app-layer seal), backed by client/core.
}
