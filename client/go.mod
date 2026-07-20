module github.com/0gfoundation/0g-pc/client

go 1.24.0

toolchain go1.24.7

// The client core will import the shared protocol module. Kept as a local
// replace for multi-module development in this repo until protocol is tagged.
require github.com/0gfoundation/0g-pc/protocol v0.0.0

require (
	github.com/cloudflare/circl v1.6.4 // indirect
	github.com/gowebpki/jcs v1.0.1 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
)

replace github.com/0gfoundation/0g-pc/protocol => ../protocol
