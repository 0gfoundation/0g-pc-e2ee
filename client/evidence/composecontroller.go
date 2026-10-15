package evidence

// composecontroller.go holds the one exception the review makes to its rule that a
// container holding the container runtime's socket is BLOCKING: 0G's own controller, at a
// listed release, under the conditions the broker enforces in the controller's code.
//
// WHY AN EXCEPTION AT ALL. Every provider on the 2026-10-10 sweep mounted
// /var/run/docker.sock into 0g-controller — it is how the broker deployment works, not
// one operator's choice. The broker team's account of why (broker #759): the controller
// swaps the broker and event images on upgrade, may create no new container unless the
// compose sets ZG_CONTROLLER_ENGINES=on, may swap an image only as repo@digest, and
// records each swap in RTMR3 before executing it. With that, the socket is a reviewed
// capability of a known program rather than an unexplained escape hatch, and reporting
// it blocking on every deployment would teach readers to skim past the one finding that
// matters most when it appears anywhere else.
//
// WHY JUSTIFY AND NOT SILENCE. Those limits are the controller's CODE at a particular
// digest. This review reads a manifest; it cannot see code, and it does not adjudicate.
// So the finding stays, at Justify, saying what it rests on — and on any build the
// release list does not name, the limits are not known to hold and it stays Blocking.
//
// WHY THESE CONDITIONS. Each closes a way to put the socket in the hands of something
// #759 does not govern. The broker image ships three programs, so the service has to RUN
// the controller, not merely be named after it. The image has to be a listed release,
// since an unlisted build is unknown code. Any service key beyond the few a controller
// needs (controllerKeys), extra host paths, and any mention of the engine flag each widen
// what the holder can reach beyond what #759 describes. And any OTHER blocking finding
// on the service keeps this one blocking too: an exception granted to a service the
// review already refuses would read as approval of it.

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// controllerService is the compose service the exception applies to. Necessary, not
	// sufficient: the name is the operator's to choose.
	controllerService = "0g-controller"
	// controllerCommand is the program in the broker image the exception is about.
	controllerCommand = "0g-controller"
	// controllerEnginesEnv is the flag broker #759 gates container creation on.
	controllerEnginesEnv = "ZG_CONTROLLER_ENGINES"
)

// runtimeDockerSockets are the spellings of the docker socket the exception covers. Not
// all of dockerSockets: #759 describes what the controller does through the DOCKER API,
// and a containerd socket is a different capability nobody has accounted for.
var runtimeDockerSockets = map[string]bool{
	"/var/run/docker.sock": true,
	"/run/docker.sock":     true,
}

// justifyControllerRuntimeSocket applies the exception to the findings reviewService
// produced for one service, from index start on. It runs before the findings are sorted,
// so the indices reviewVolumes recorded still point at the findings it added.
func (r *ComposeReview) justifyControllerRuntimeSocket(name string, body *yaml.Node, svc ReviewedService,
	mounts *mountIndex, start int) {
	if name != controllerService {
		return
	}
	var socketAt []int
	otherBlocking := ""
	for i := start; i < len(r.Findings); i++ {
		f := r.Findings[i]
		if f.Service != name || f.Severity != SeverityBlocking {
			continue
		}
		if mounts.runtimeSocketAt[i] {
			socketAt = append(socketAt, i)
		} else if otherBlocking == "" {
			otherBlocking = f.Key
		}
	}
	if len(socketAt) == 0 {
		return
	}

	rel, why := controllerEligible(body, svc, mounts, r.releases)
	if why == "" && otherBlocking != "" {
		why = fmt.Sprintf("the service has another blocking finding (%s)", otherBlocking)
	}
	for _, i := range socketAt {
		if why != "" {
			// Kept blocking, and saying why, so a reader of a deployment that is close
			// knows the one thing that stands between it and the exception.
			r.Findings[i].Detail += fmt.Sprintf(". The exception for 0G's controller does not apply: %s", why)
			continue
		}
		r.Findings[i].Severity = SeverityJustify
		r.Findings[i].Detail += fmt.Sprintf(". JUSTIFIED rather than blocking: this is 0G's controller at listed "+
			"release %s, running as %s, with no service keys beyond the ones the exception covers (so no "+
			"entrypoint override, privileges, capabilities, devices, host namespaces or env_file), no host path "+
			"beyond the docker and guest-agent sockets, and %s absent — the conditions under "+
			"which broker #759 limits what it does with the socket (no new container; an image swap only as "+
			"repo@digest for broker and event, recorded in RTMR3 first; the full list is the broker repository's "+
			"doc/controller-design.md §3.4). Those limits are the controller's code at this digest: this review "+
			"cannot see them, and they do not hold on any other build",
			rel.Version, controllerCommand, controllerEnginesEnv)
	}
}

// controllerKeys are the service keys the exception covers: exactly the eleven every
// controller on the fleet writes (all seven providers, 2026-10-15), plus three that only
// describe the container's lifecycle. Anything else costs the exception.
//
// An ALLOWLIST, not a list of dangerous keys, because the second kind is never finished:
// `devices`, `ipc: host`, `uts: host` and `userns_mode: host` each reach past what #759
// describes, and none of them is blocking on its own — GPU services need devices — so
// "no other blocking finding" did not catch them, and a denylist missed them. With an
// allowlist, a key nobody has thought about is a reason to stay blocking, not a gap.
// `volumes` and `environment` are on it because they are checked separately below.
var controllerKeys = map[string]bool{
	"image": true, "command": true, "container_name": true, "environment": true, "volumes": true,
	"depends_on": true, "networks": true, "ports": true, "healthcheck": true, "logging": true,
	"restart": true,
	"labels":  true, "stop_grace_period": true, "stop_signal": true,
}

// controllerEligible reports whether a service meets the exception's conditions, and
// when it does not, the first condition it fails — phrased as what is wrong. rels is the
// release list the whole run uses, so this and the baseline cannot disagree about a
// digest.
func controllerEligible(body *yaml.Node, svc ReviewedService, mounts *mountIndex, rels BrokerReleases) (BrokerRelease, string) {
	if !svc.Pinned() {
		return BrokerRelease{}, "its image is not pinned by digest"
	}
	if svc.Image != rels.Repository {
		return BrokerRelease{}, fmt.Sprintf("its image is %s, not 0G's broker image", svc.Image)
	}
	rel, ok := rels.Lookup(svc.Image, svc.Digest)
	if !ok {
		return BrokerRelease{}, fmt.Sprintf("%s@%s is not a listed release (brokerreleases.json lists %s), so "+
			"the controller code that would limit the socket is not known to be there",
			svc.Image, shortDigest(svc.Digest), listedVersions(rels))
	}

	for i := 0; i+1 < len(body.Content); i += 2 {
		if k := body.Content[i].Value; !controllerKeys[k] {
			return BrokerRelease{}, fmt.Sprintf("it sets %s, which is not among the keys the exception covers "+
				"(%s); each further key is something #759 does not describe", k, strings.Join(sortedTrue(controllerKeys), ", "))
		}
	}
	if cmd, ok := commandOf(mapValue(body, "command")); !ok || cmd != controllerCommand {
		return BrokerRelease{}, fmt.Sprintf("its command is not %s, so the process holding the socket is not "+
			"the controller", controllerCommand)
	}
	if why := enginesSet(mapValue(body, "environment")); why != "" {
		return BrokerRelease{}, why
	}
	if why := onlySocketHostMounts(mapValue(body, "volumes"), mounts); why != "" {
		return BrokerRelease{}, why
	}
	return rel, ""
}

func sortedTrue(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// commandOf reads a command written as one word, as a scalar or a one-element list.
func commandOf(n *yaml.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	if n.Kind == yaml.ScalarNode {
		return strings.TrimSpace(n.Value), true
	}
	if parts, ok := nodeStrings(n); ok && len(parts) == 1 {
		return parts[0], true
	}
	return "", false
}

// enginesSet reports why the controller's engine flag disqualifies the service, or ""
// when the environment does not mention it.
//
// ABSENT, and only absent. The broker enables engine creation on exactly "on"
// (ctrl.go: os.Getenv(EnginesEnvVar) == "on"), so `=false` is off in v0.5.4's code — but
// the exception rests on reading the manifest, not on how one build parses a string, and
// the broker's own guidance to verifiers is phrased the same way: "a verifier that
// requires that variable to be absent" (doc/rtmr3-records.md §4.4). No deployment on the
// fleet sets it, so the strict reading costs nothing. A value the HOST supplies
// (`- NAME`, `NAME:`, `${…}`) is presence too.
func enginesSet(env *yaml.Node) string {
	set := func(how string) string {
		return fmt.Sprintf("its environment sets %s (%s); the exception requires the variable to be absent, "+
			"which is the one state in which the controller can create no container", controllerEnginesEnv, how)
	}
	switch {
	case env == nil:
		return ""
	case env.Kind == yaml.SequenceNode:
		for _, e := range env.Content {
			if e.Kind != yaml.ScalarNode {
				return "an environment entry could not be read"
			}
			k, v, hasValue := strings.Cut(strings.TrimSpace(e.Value), "=")
			if strings.TrimSpace(k) != controllerEnginesEnv {
				continue
			}
			if !hasValue {
				return set("passed through from the host")
			}
			return set(fmt.Sprintf("to %q", v))
		}
		return ""
	case env.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(env.Content); i += 2 {
			if strings.TrimSpace(env.Content[i].Value) != controllerEnginesEnv {
				continue
			}
			if v := env.Content[i+1]; v.Kind == yaml.ScalarNode && v.Tag != "!!null" {
				return set(fmt.Sprintf("to %q", v.Value))
			}
			return set("passed through from the host")
		}
		return ""
	}
	return "the environment could not be read"
}

// onlySocketHostMounts reports the first host path the service mounts beyond the docker
// and guest-agent sockets, or "" when there is none. A named volume is not a host path
// unless the top-level section makes it one; a relative bind always is.
func onlySocketHostMounts(vols *yaml.Node, mounts *mountIndex) string {
	if vols == nil {
		return ""
	}
	if vols.Kind != yaml.SequenceNode {
		return "its volumes could not be read"
	}
	for _, entry := range vols.Content {
		src, _, _, ok := parseMount(entry)
		switch {
		case !ok:
			return "a mount could not be read"
		case src == "":
			continue
		case isNamedVolume(src):
			if decl, declared := mounts.volumes[src]; declared && (decl.HostPath != "" || decl.Opaque != "") {
				return fmt.Sprintf("the volume %s is not an ordinary named volume", src)
			}
		case !strings.HasPrefix(src, "/"):
			return fmt.Sprintf("it mounts the relative host path %s", src)
		default:
			clean := path.Clean(src)
			if !runtimeDockerSockets[clean] && !guestAgentSockets[clean] {
				return fmt.Sprintf("it mounts the host path %s", clean)
			}
		}
	}
	return ""
}
