// Package route is a pure scoring function: (candidates, stats) -> ranked order.
// The router and the client call the *same* scorer so their ordering always
// agrees, without the client needing global fleet data. The live fleet view
// (who is up, load, price) stays in the router and is passed in as stats.
//
// Contract: router <-> client. Kept dependency-free and self-contained so it
// remains a separable package (or a separate module later) without touching
// the confidentiality/proof contract.
package route
