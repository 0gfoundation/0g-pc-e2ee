module github.com/0gfoundation/0g-pc-e2ee/client

go 1.24.0

toolchain go1.26.9

// The client core will import the shared protocol module. Kept as a local
// replace for multi-module development in this repo until protocol is tagged.
require github.com/0gfoundation/0g-pc-e2ee/protocol v0.0.0

require (
	// The loader dstack's docker compose v2.26.0 links; evidence/compose loads provider
	// manifests with it. Pinned with its parsing dependencies — see
	// evidence/compose/composeload.go before moving any of them.
	github.com/compose-spec/compose-go/v2 v2.0.2
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/google/go-tdx-guest v0.3.2-0.20260730200302-2108462acb71
	github.com/prometheus/client_golang v1.20.5
	github.com/prometheus/client_model v0.6.1
	golang.org/x/crypto v0.45.0
	golang.org/x/sync v0.10.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.4 // indirect
	github.com/distribution/reference v0.5.0 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/gowebpki/jcs v1.0.1 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-shellwords v1.0.12 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20240112132812-db7319d0e0e3 // indirect
	golang.org/x/sys v0.38.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

replace github.com/0gfoundation/0g-pc-e2ee/protocol => ../protocol
