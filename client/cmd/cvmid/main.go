// Command cvmid publishes this CVM's identity to the other containers of the
// same dstack app, then exits. It is an init container, not a service: it runs
// once at boot, writes two small files to a shared volume, and is done.
//
// Why it exists at all — two problems that look unrelated and have one cause:
//
//  1. Several CVMs can back one app_id (deploy/phala/blue-green.md "Scaling one
//     side"), and the platform picks which one a connection reaches. Every
//     container in those CVMs is byte-identical, so nothing inside them can say
//     WHICH replica it is. The gateway needs that for its log fields and metric
//     labels; the co-located Prometheus agent needs it or its self-scrape series
//     (remote_write queue health — precisely the signal that tells you a replica
//     has gone deaf) collide in the shared remote-write store, since its external
//     labels and target labels are identical across replicas too.
//  2. Only the dstack guest agent knows the answer, and it is reached over a
//     PRIVILEGED unix socket: the same endpoint derives keys and issues quotes.
//
// Doing the lookup here rather than in each consumer keeps that socket off the
// long-running gateway — the container that handles user prompts — which reads a
// derived file instead. It does NOT make the socket exclusive: dstack-ingress
// mounts it too, and always has, for the cert binding the attestation story rests
// on. The honest framing is that this adds a holder that exits, not a holder that
// runs for the life of the CVM.
//
// The Prometheus agent could not do the lookup for itself in any case: compose
// interpolation happens at deploy time and cannot see a value the runtime assigns
// per CVM, and a container's environment cannot be written from outside once it
// exists. A file can.
//
// Outputs (either may be omitted):
//
//   - -out-identity: {"instance_id","app_id","app_name","compose_hash"}, read by
//     the gateway (client/dstack.ReadIdentityFile).
//   - -prom-sd PATH=TARGET, repeatable: a Prometheus file_sd document pinning
//     TARGET with the identity as TARGET LABELS. Prometheus watches the file and
//     picks it up without a restart, which is what makes this an init container
//     instead of an ordering problem.
//
// One document per scrape job, not one shared file: a file_sd document belongs to
// the job that references it, so pointing two jobs at one file would make each
// discover the other's target.
//
// Target labels are the ONLY mechanism that works here, which is why this exists
// rather than the exporter stamping its own identity. Prometheus synthesises up,
// scrape_duration_seconds, scrape_samples_scraped,
// scrape_samples_post_metric_relabeling and scrape_series_added from target
// labels alone — never from the exposition — so an exporter-side label cannot
// reach them. `up` makes it obvious: it exists precisely when the exposition
// could NOT be read. Per-replica `up` is the signal most worth alerting on, so
// the label has to come from the scraper's side of the boundary.
//
// Exit codes are load-bearing, because the compose gates other services on this
// one completing: a failed IDENTITY LOOKUP exits 0 (the files are still written,
// minus the labels — losing a telemetry dimension must never keep the gateway
// from serving), while a failed WRITE exits 1 (the volume is not mounted the way
// the compose says, which is a broken deploy and should be loud).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/client/dstack"
)

func main() {
	socket := flag.String("dstack-socket", dstack.DefaultSocket,
		"path to the dstack guest-agent unix socket to read this CVM's identity from")
	outIdentity := flag.String("out-identity", "",
		"write the identity as JSON to this path (read by the gateway); empty skips it")
	var promSD promSDFlag
	flag.Var(&promSD, "prom-sd",
		"PATH=TARGET: write a Prometheus file_sd document to PATH pinning TARGET (e.g. "+
			"/run/identity/sd/gateway.json=gateway:9464) with the identity as target labels. "+
			"Repeat once per scrape job — two jobs must not share one document, or each would "+
			"discover the other's target")
	flag.Parse()

	if *outIdentity == "" && len(promSD) == 0 {
		fmt.Fprintln(os.Stderr, "cvmid: nothing to do: set -out-identity and/or -prom-sd")
		os.Exit(2)
	}

	// Best-effort by design: outside a CVM there is no socket, and inside one a
	// wedged agent must not block the boot of everything gated on this container.
	// Report it on stderr (dstack captures it as a log record) and carry on writing
	// the unlabelled files.
	ctx, cancel := context.WithTimeout(context.Background(), dstack.DefaultTimeout)
	info, err := dstack.FetchInfo(ctx, *socket)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cvmid: identity unavailable, writing unlabelled outputs: %v\n", err)
		info = dstack.Info{}
	}

	// No identity means no identity file: an empty one would only fail
	// ReadIdentityFile's validation at the far end, which is a worse signal than
	// its absence. The reader (the gateway) treats both the same way — warn and
	// serve without the dimension.
	//
	// Removing a leftover matters as much as writing a new one. The volume outlives
	// any single boot, so a file from an earlier one would otherwise be read as
	// current. Within one CVM that is harmless (the id is stable), but a dstack
	// in-place upgrade reuses the disk under a NEW app_id — and instance_id is
	// derived from it — so the stale file would name a replica that no longer
	// exists. Missing telemetry beats confidently wrong telemetry.
	if *outIdentity != "" {
		if info.InstanceID != "" {
			if err := dstack.WriteIdentityFile(*outIdentity, info); err != nil {
				fmt.Fprintf(os.Stderr, "cvmid: %v\n", err)
				os.Exit(1)
			}
		} else if err := clearIdentityFile(*outIdentity); err != nil {
			fmt.Fprintf(os.Stderr, "cvmid: %v\n", err)
			os.Exit(1)
		}
	}
	for _, sd := range promSD {
		if err := writePromSD(sd.path, sd.target, info); err != nil {
			fmt.Fprintf(os.Stderr, "cvmid: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stdout, "cvmid: instance_id=%q app_id=%q\n", info.InstanceID, info.AppID)
}

// promSDOutput is one -prom-sd PATH=TARGET pair: the document to write and the
// scrape target it pins.
type promSDOutput struct{ path, target string }

// promSDFlag collects repeated -prom-sd pairs. One per scrape job.
type promSDFlag []promSDOutput

func (f *promSDFlag) String() string {
	parts := make([]string, 0, len(*f))
	for _, o := range *f {
		parts = append(parts, o.path+"="+o.target)
	}
	return strings.Join(parts, ",")
}

// Set parses one PATH=TARGET pair. It splits on the FIRST "=" — a scrape target
// is host:port and never contains one, so any "=" belongs to the path, which in
// practice has none either.
func (f *promSDFlag) Set(v string) error {
	path, target, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("expected PATH=TARGET, got %q", v)
	}
	if path == "" || target == "" {
		return fmt.Errorf("both PATH and TARGET must be non-empty, got %q", v)
	}
	*f = append(*f, promSDOutput{path: path, target: target})
	return nil
}

// clearIdentityFile removes a leftover identity file, treating an already-absent
// one as success. Failing to remove one IS an error worth exiting on: it means
// the volume is not writable the way the compose says, the same condition the
// write path exits for.
func clearIdentityFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale identity file %s: %w", path, err)
	}
	return nil
}

// promSDEntry is one entry of a Prometheus file_sd document: the targets to
// scrape and the labels to attach to everything scraped from them.
type promSDEntry struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// writePromSD writes the file_sd document for target, labelled with whatever of
// info is available.
//
// When the identity is missing the document is still written, with targets and no
// labels: that is the difference between "the agent scrapes itself, unlabelled"
// (recoverable, and honest about what we know) and "the agent has no self-scrape
// target at all" (the health signal disappears entirely).
//
// Every scrape job gets its identity this way — nothing is labelled exporter-side
// — so there is no honor_labels conflict to reason about and the per-scrape series
// (up and friends) are labelled too.
func writePromSD(path, target string, info dstack.Info) error {
	entry := promSDEntry{Targets: []string{target}}
	labels := map[string]string{}
	if info.InstanceID != "" {
		labels["instance_id"] = info.InstanceID
	}
	if info.AppID != "" {
		labels["app_id"] = info.AppID
	}
	if len(labels) > 0 {
		entry.Labels = labels
	}
	body, err := json.MarshalIndent([]promSDEntry{entry}, "", "  ")
	if err != nil {
		return fmt.Errorf("prometheus file_sd %s: %w", path, err)
	}
	// Same publish path as the identity file: atomic and world-readable, both of
	// which this file needs — Prometheus watches it and reloads on change, and it
	// runs as nobody while this container runs as root.
	return dstack.PublishFile(path, append(body, '\n'))
}
