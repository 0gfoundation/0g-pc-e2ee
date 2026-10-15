package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v054 is the broker release the embedded list carries.
const v054 = "ghcr.io/0gfoundation/0g-serving-broker@sha256:951f4c7971f87377ab077639a5a84d2aed8945460494da076ff8466ea1ee90b5"

// eligibleController is a controller that meets every condition. Each case below breaks
// exactly one, so a case that still relaxes the finding has found a hole.
const eligibleController = `services:
  0g-controller:
    image: ` + v054 + `
    command: 0g-controller
    environment:
      - CONFIG_FILE=/etc/config/config.yaml
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - /var/run/docker.sock:/var/run/docker.sock
      - zg-tee:/var/run/zg-tee
volumes:
  zg-tee: {}
`

// dockerSockFinding returns the finding about a service's docker socket.
func dockerSockFinding(t *testing.T, r ComposeReview, service string) Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Service == service && f.Key == "volumes" && strings.Contains(f.Detail, "docker.sock") {
			return f
		}
	}
	t.Fatalf("no docker.sock finding for %s:\n%+v", service, r.Findings)
	return Finding{}
}

func TestControllerException_Applies(t *testing.T) {
	f := dockerSockFinding(t, reviewOf(t, manifest(eligibleController)), "0g-controller")
	// And with the recorded healthcheck, which every controller on the fleet carries.
	withHC := strings.Replace(eligibleController, "    command: 0g-controller\n", "    command: 0g-controller\n"+
		"    healthcheck:\n      test: [CMD-SHELL, \"grep -q '0g-controller' /proc/1/cmdline\"]\n      interval: 30s\n", 1)
	if g := dockerSockFinding(t, reviewOf(t, manifest(withHC)), "0g-controller"); g.Severity != SeverityJustify {
		t.Fatalf("the recorded healthcheck cost the exception:\n%s", g.Detail)
	}
	if f.Severity != SeverityJustify {
		t.Fatalf("severity = %s, want justify:\n%s", f.Severity, f.Detail)
	}
	// It says what it rests on, so the relaxation is an argument a reader can check
	// rather than a finding that quietly went away.
	for _, want := range []string{"v0.5.4", "#759", "controller-design.md", "do not hold on any other build"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail does not mention %q:\n%s", want, f.Detail)
		}
	}
}

// Each condition, broken alone, keeps the finding blocking — and the detail says which.
func TestControllerException_EachConditionIsLoadBearing(t *testing.T) {
	sub := func(old, new string) string {
		if !strings.Contains(eligibleController, old) {
			t.Fatalf("fixture has no %q", old)
		}
		return strings.Replace(eligibleController, old, new, 1)
	}
	envLine := "      - CONFIG_FILE=/etc/config/config.yaml\n"
	for _, tc := range []struct{ name, doc, says string }{
		{"an unlisted release",
			sub("sha256:951f4c79", "sha256:ec5df834"), ""},
		{"v0.5.1, the build cn-20 runs",
			strings.Replace(eligibleController, "@sha256:951f4c7971f87377ab077639a5a84d2aed8945460494da076ff8466ea1ee90b5",
				"@sha256:ec5df8347f91c3b28a6638db4e24dba343799c0a3a7e2cdd44845a3a27f2e734", 1), "not a listed release"},
		{"a tag instead of a digest",
			sub(v054, "ghcr.io/0gfoundation/0g-serving-broker:v0.5.4"), "not pinned"},
		{"another repository",
			sub("ghcr.io/0gfoundation/0g-serving-broker@", "ghcr.io/someone/0g-serving-broker@"), "not 0G's broker image"},
		// The broker image ships three programs. A service named 0g-controller running
		// the inference server holds the socket in code #759 does not govern.
		{"another program from the same image",
			sub("command: 0g-controller", "command: 0g-inference-server"), "command is not"},
		{"no command at all",
			sub("    command: 0g-controller\n", ""), "command is not"},
		{"an entrypoint override",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    entrypoint: [sh, -c]\n"), "entrypoint"},
		{"privileged",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    privileged: true\n"), ""},
		{"an added capability",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    cap_add: [NET_ADMIN]\n"), "cap_add"},
		// None of these is blocking on its own — GPU services need devices — so "no other
		// blocking finding" did not catch them. The allowlist does.
		{"a host device",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    devices: [/dev/sda:/dev/sda]\n"), "devices"},
		{"the host's IPC namespace",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    ipc: host\n"), "ipc"},
		{"the host's UTS namespace",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    uts: host\n"), "uts"},
		{"no user-namespace remapping",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    userns_mode: host\n"), "userns_mode"},
		{"the host's network",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    network_mode: host\n"), "network_mode"},
		{"a security option",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    security_opt: [seccomp:unconfined]\n"), "security_opt"},
		{"another container's volumes",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    volumes_from: [other]\n"), "volumes_from"},
		{"engines on",
			sub(envLine, envLine+"      - ZG_CONTROLLER_ENGINES=on\n"), "sets ZG_CONTROLLER_ENGINES"},
		{"engines on, map form",
			sub("    environment:\n"+envLine, "    environment:\n      ZG_CONTROLLER_ENGINES: \"on\"\n"), "sets ZG_CONTROLLER_ENGINES"},
		// The host decides, which is the same as on for this purpose.
		{"engines passed through from the host",
			sub(envLine, envLine+"      - ZG_CONTROLLER_ENGINES\n"), "host"},
		{"engines interpolated from the host",
			sub(envLine, envLine+"      - ZG_CONTROLLER_ENGINES=${ENGINES}\n"), "`$`"},
		// docker compose interpolates before anything runs, and every check reads the text
		// as written. These three each passed while the .env decided what ran.
		{"the engine flag's NAME from the .env (K=ZG_CONTROLLER_ENGINES)",
			sub(envLine, envLine+"      - ${K}=on\n"), "`$`"},
		{"a host root from the .env (HOSTROOT=/)",
			sub("      - zg-tee:/var/run/zg-tee\n", "      - zg-tee:/var/run/zg-tee\n      - ${HOSTROOT}:/host\n"), "`$`"},
		{"an interpolated label",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    labels: {a: \"${X}\"}\n"), "labels.a"},
		{"compose's escaped dollar",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    labels: {a: \"$$X\"}\n"), "`$`"},
		// A healthcheck is a program docker runs inside this container, with the socket.
		{"a healthcheck that is a second program",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    healthcheck:\n      test: [CMD-SHELL, \"curl --unix-socket /var/run/docker.sock http://x/containers/json\"]\n"), "healthcheck runs"},
		{"the recorded healthcheck in string form",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    healthcheck:\n      test: \"grep -q '0g-controller' /proc/1/cmdline\"\n"), "healthcheck runs"},
		{"a healthcheck key beyond timing",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    healthcheck:\n      test: [CMD-SHELL, \"grep -q '0g-controller' /proc/1/cmdline\"]\n      start_interval: 1s\n"), "start_interval"},
		// A variable can change what the process does without changing the image.
		{"a variable outside the allowlist",
			sub(envLine, envLine+"      - LD_PRELOAD=/etc/config/x.so\n"), "LD_PRELOAD"},
		// Named volumes: declared, local, created by this manifest.
		{"an undeclared named volume",
			sub("      - zg-tee:/var/run/zg-tee\n", "      - zg-tee:/var/run/zg-tee\n      - hostroot:/host\n"), "does not declare"},
		{"an external volume",
			strings.Replace(sub("      - zg-tee:/var/run/zg-tee\n", "      - zg-tee:/var/run/zg-tee\n      - ext:/ext\n"),
				"volumes:\n  zg-tee: {}\n", "volumes:\n  zg-tee: {}\n  ext: {external: true}\n", 1), "ordinary local volume"},
		{"a volume declared from the .env",
			strings.Replace(sub("      - zg-tee:/var/run/zg-tee\n", "      - zg-tee:/var/run/zg-tee\n      - v:/v\n"),
				"volumes:\n  zg-tee: {}\n", "volumes:\n  zg-tee: {}\n  v: {name: \"${VOL}\"}\n", 1), "contains `$`"},
		{"environment from a file the manifest does not contain",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    env_file: ./controller.env\n"), "env_file"},
		{"another absolute host path",
			sub("      - zg-tee:/var/run/zg-tee\n", "      - zg-tee:/var/run/zg-tee\n      - /opt/data:/data\n"), "/opt/data"},
		{"a relative host path",
			sub("      - zg-tee:/var/run/zg-tee\n", "      - zg-tee:/var/run/zg-tee\n      - ./logs/controller:/var/log\n"), "relative"},
		// A blocking key outside the allowlist is refused by the allowlist first; the
		// other-blocking rule stays behind it for any blocking finding an allowed key grows.
		{"a blocking key",
			sub("    command: 0g-controller\n", "    command: 0g-controller\n    pid: host\n"), "pid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dockerSockFinding(t, reviewOf(t, manifest(tc.doc)), "0g-controller")
			if f.Severity != SeverityBlocking {
				t.Fatalf("relaxed to %s:\n%s", f.Severity, f.Detail)
			}
			if tc.says != "" && !strings.Contains(f.Detail, tc.says) {
				t.Errorf("detail does not say why (%q):\n%s", tc.says, f.Detail)
			}
		})
	}
}

// Any value at all costs the exception, including the ones v0.5.4 reads as off: the
// exception rests on the manifest leaving the variable ABSENT, which is how the broker
// states it to verifiers, not on how one build parses a string.
func TestControllerException_AnyEnginesValueCostsIt(t *testing.T) {
	for _, v := range []string{"off", "false", "0", "OFF", ""} {
		doc := strings.Replace(eligibleController, "      - CONFIG_FILE=/etc/config/config.yaml\n",
			"      - CONFIG_FILE=/etc/config/config.yaml\n      - ZG_CONTROLLER_ENGINES="+v+"\n", 1)
		f := dockerSockFinding(t, reviewOf(t, manifest(doc)), "0g-controller")
		if f.Severity != SeverityBlocking || !strings.Contains(f.Detail, "absent") {
			t.Errorf("ZG_CONTROLLER_ENGINES=%q: severity %s:\n%s", v, f.Severity, f.Detail)
		}
	}
}

// The release list is the one the caller passes — the same one CheckCompose gets — not
// one the review reads for itself. Otherwise a run given a different list would judge
// the same digest two ways in one report.
func TestControllerException_UsesTheReleaseListItIsGiven(t *testing.T) {
	raw, hash := appComposeFor(t, manifest(eligibleController))
	for _, tc := range []struct {
		name string
		rels BrokerReleases
		want Severity
	}{
		{"the embedded list", builtinReleases(t), SeverityJustify},
		{"an empty list", BrokerReleases{Repository: brokerRepoName}, SeverityBlocking},
		{"a list without this digest", BrokerReleases{Repository: brokerRepoName,
			Releases: []BrokerRelease{{"v9", "sha256:" + strings.Repeat("b", 64)}}}, SeverityBlocking},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ReviewCompose(raw, hash, tc.rels)
			if err != nil {
				t.Fatal(err)
			}
			if f := dockerSockFinding(t, r, "0g-controller"); f.Severity != tc.want {
				t.Fatalf("severity %s, want %s:\n%s", f.Severity, tc.want, f.Detail)
			}
		})
	}
}

// The exception is the controller's, not the image's. broker and event run the same
// release, and neither is a program #759 describes.
func TestControllerException_IsOnlyForTheController(t *testing.T) {
	doc := strings.Replace(eligibleController, "  0g-controller:\n", "  0g-serving-provider-broker:\n", 1)
	f := dockerSockFinding(t, reviewOf(t, manifest(doc)), "0g-serving-provider-broker")
	if f.Severity != SeverityBlocking {
		t.Fatalf("the broker service holding the socket was relaxed:\n%s", f.Detail)
	}
	if strings.Contains(f.Detail, "exception") {
		t.Errorf("a service that is not the controller was told about the controller's exception:\n%s", f.Detail)
	}
}

// Only a DIRECT bind of the docker socket is covered. The same socket delivered through a
// named volume, and a containerd socket, are capabilities nobody has accounted for.
func TestControllerException_CoversOnlyTheDirectDockerBind(t *testing.T) {
	t.Run("through a named volume", func(t *testing.T) {
		doc := strings.Replace(eligibleController, "      - /var/run/docker.sock:/var/run/docker.sock\n",
			"      - dsock:/var/run/docker.sock\n", 1)
		doc = strings.Replace(doc, "volumes:\n  zg-tee: {}\n",
			"volumes:\n  zg-tee: {}\n  dsock:\n    driver_opts:\n      type: none\n      o: bind\n      device: /var/run/docker.sock\n", 1)
		f := dockerSockFinding(t, reviewOf(t, manifest(doc)), "0g-controller")
		if f.Severity != SeverityBlocking {
			t.Fatalf("relaxed:\n%s", f.Detail)
		}
	})
	t.Run("containerd", func(t *testing.T) {
		doc := strings.Replace(eligibleController, "/var/run/docker.sock:/var/run/docker.sock",
			"/var/run/containerd/containerd.sock:/var/run/containerd/containerd.sock", 1)
		for _, f := range reviewOf(t, manifest(doc)).Findings {
			if f.Service == "0g-controller" && strings.Contains(f.Detail, "containerd.sock") && f.Severity != SeverityBlocking {
				t.Fatalf("relaxed:\n%s", f.Detail)
			}
		}
	})
}

// The real deployments. testnet runs v0.5.4 and meets every condition; cn-20 runs v0.5.1,
// and its finding stays blocking and says so.
func TestControllerException_OnTheRecordedDeployments(t *testing.T) {
	load := func(name string) ComposeReview {
		t.Helper()
		doc, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return reviewOf(t, manifest(string(doc)))
	}
	if f := dockerSockFinding(t, reviewTestnet(t), "0g-controller"); f.Severity != SeverityJustify {
		t.Errorf("testnet: severity %s:\n%s", f.Severity, f.Detail)
	}
	f := dockerSockFinding(t, load("cn20-services.yml"), "0g-controller")
	if f.Severity != SeverityBlocking || !strings.Contains(f.Detail, "not a listed release") {
		t.Errorf("cn-20: severity %s:\n%s", f.Severity, f.Detail)
	}
}
