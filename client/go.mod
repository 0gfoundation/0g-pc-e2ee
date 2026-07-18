module github.com/0gfoundation/0g-pc/client

go 1.23

// The client core will import the shared protocol module. Kept as a local
// replace for multi-module development in this repo until protocol is tagged.
require github.com/0gfoundation/0g-pc/protocol v0.0.0

replace github.com/0gfoundation/0g-pc/protocol => ../protocol
