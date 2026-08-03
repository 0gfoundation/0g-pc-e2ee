// Package sig implements the concrete secp256k1/keccak signature recovery the
// §8 verifier needs, satisfying proof.RecoverFunc. It is the "heavy crypto"
// half of the seam: protocol/proof stays dependency-light and portable, while
// this package (in the client module, alongside dcap/chain) carries the curve
// dependency.
//
// It uses github.com/decred/dcrd/dcrec/secp256k1/v4 — the exact library
// go-ethereum wraps for non-cgo secp256k1 — so recovery is byte-identical to the
// broker's go-ethereum signatures without pulling go-ethereum into the client.
// A broker-produced KAT (recover_test.go) proves that compatibility.
package sig

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Recover recovers the 0x-prefixed (lowercase) Ethereum address that produced an
// EIP-191 personal_sign signature over text. It satisfies proof.RecoverFunc.
//
// sig is the 65-byte [R‖S‖V] signature the broker emits (go-ethereum layout),
// with V in {0,1} or {27,28}. Recovery is fail-closed: any malformed input
// returns an error rather than a zero address.
func Recover(text string, sig []byte) (string, error) {
	if len(sig) != 65 {
		return "", fmt.Errorf("sig: want 65-byte signature, got %d", len(sig))
	}

	// Normalize the recovery id to 0..3. go-ethereum/broker use {0,1} raw or add
	// 27; nothing here expects EIP-155 chain-encoded v (that is for transactions).
	v := sig[64]
	if v >= 27 {
		v -= 27
	}
	if v > 3 {
		return "", fmt.Errorf("sig: invalid recovery id %d", sig[64])
	}

	// decred's RecoverCompact wants [V‖R‖S] with V 27-based at the FRONT, whereas
	// go-ethereum emits [R‖S‖V]. Reorder into the compact layout.
	compact := make([]byte, 65)
	compact[0] = 27 + v
	copy(compact[1:33], sig[0:32])
	copy(compact[33:65], sig[32:64])

	pub, _, err := ecdsa.RecoverCompact(compact, eip191Hash(text))
	if err != nil {
		return "", fmt.Errorf("sig: recover: %w", err)
	}
	return addressFromPubKey(pub), nil
}

// eip191Hash = keccak256("\x19Ethereum Signed Message:\n" + len(text) + text),
// matching go-ethereum's accounts.TextHash (personal_sign). len is byte length.
func eip191Hash(text string) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(text))))
	h.Write([]byte(text))
	return h.Sum(nil)
}

// addressFromPubKey = "0x" + hex(keccak256(uncompressed_pubkey_without_prefix)[12:]).
func addressFromPubKey(pub *secp256k1.PublicKey) string {
	raw := pub.SerializeUncompressed() // 0x04 ‖ X(32) ‖ Y(32)
	h := sha3.NewLegacyKeccak256()
	h.Write(raw[1:])
	sum := h.Sum(nil)
	return "0x" + hex.EncodeToString(sum[12:])
}
