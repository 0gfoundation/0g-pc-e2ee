module github.com/0gfoundation/0g-pc-e2ee/client

go 1.24.0

toolchain go1.24.7

// The client core will import the shared protocol module. Kept as a local
// replace for multi-module development in this repo until protocol is tagged.
require github.com/0gfoundation/0g-pc-e2ee/protocol v0.0.0

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/google/go-tdx-guest v0.3.2-0.20260730200302-2108462acb71
	golang.org/x/crypto v0.45.0
	golang.org/x/sync v0.10.0
)

require (
	github.com/cloudflare/circl v1.6.4 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/gowebpki/jcs v1.0.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

replace github.com/0gfoundation/0g-pc-e2ee/protocol => ../protocol
