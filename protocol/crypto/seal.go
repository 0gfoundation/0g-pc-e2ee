package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// HPKE cipher suite (RFC 9180), base mode (anonymous sender):
//
//	KEM   DHKEM(X25519, HKDF-SHA256)
//	KDF   HKDF-SHA256
//	AEAD  ChaCha20-Poly1305
//
// This is the single source of truth for the suite. Any non-Go implementation
// (TS/WASM, Rust) MUST use the same suite and the same sealInfo to interoperate.
var (
	kemID  = hpke.KEM_X25519_HKDF_SHA256
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_ChaCha20Poly1305
)

// sealInfo is the HPKE `info` string. It domain-separates our setups from any
// other use of the same suite and carries a protocol version, so a future
// suite/format change cannot be confused with this one.
var sealInfo = []byte("zg-pc-seal-v1")

func suite() hpke.Suite     { return hpke.NewSuite(kemID, kdfID, aeadID) }
func kemScheme() kem.Scheme { return kemID.Scheme() }

// PublicKey and PrivateKey are the recipient's marshaled X25519 KEM keys. They
// are raw bytes so they travel easily (in a quote's report_data, in config, on
// the wire). Treat them as opaque.
type (
	PublicKey  []byte
	PrivateKey []byte
)

// Sealed is one HPKE-sealed message: the encapsulated key (the sender's
// ephemeral public key) plus the AEAD ciphertext. Both must reach the recipient
// to open it. This is exactly the sealed portion of the request/response
// envelope.
type Sealed struct {
	Enc        []byte // HPKE encapsulated key
	Ciphertext []byte // AEAD ciphertext (includes the auth tag)
}

// GenerateRecipientKey creates a fresh recipient keypair. In production the
// recipient is a provider enclave and its public key is published in (and bound
// to) its attestation quote; in tests and the mock broker it is generated here.
func GenerateRecipientKey() (PrivateKey, PublicKey, error) {
	pk, sk, err := kemScheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
	}
	pub, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}
	priv, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	return priv, pub, nil
}

// Seal encrypts plaintext to the recipient's public key. aad (associated data)
// is authenticated but NOT encrypted: bind the cleartext route manifest here so
// intermediaries can read it but cannot alter it without Open failing. Pass nil
// aad when there is nothing to bind. The sender is anonymous (HPKE base mode).
func Seal(pub PublicKey, plaintext, aad []byte) (Sealed, error) {
	pk, err := kemScheme().UnmarshalBinaryPublicKey(pub)
	if err != nil {
		return Sealed{}, fmt.Errorf("bad recipient public key: %w", err)
	}
	sender, err := suite().NewSender(pk, sealInfo)
	if err != nil {
		return Sealed{}, fmt.Errorf("new sender: %w", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return Sealed{}, fmt.Errorf("sender setup: %w", err)
	}
	ct, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return Sealed{}, fmt.Errorf("seal: %w", err)
	}
	return Sealed{Enc: enc, Ciphertext: ct}, nil
}

// Open decrypts a Sealed message with the recipient's private key. aad must be
// byte-identical to what Seal was given; any difference (a tampered manifest, a
// flipped ciphertext bit, the wrong key) makes Open fail rather than return
// altered plaintext.
func Open(priv PrivateKey, s Sealed, aad []byte) ([]byte, error) {
	sk, err := kemScheme().UnmarshalBinaryPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("bad recipient private key: %w", err)
	}
	receiver, err := suite().NewReceiver(sk, sealInfo)
	if err != nil {
		return nil, fmt.Errorf("new receiver: %w", err)
	}
	opener, err := receiver.Setup(s.Enc)
	if err != nil {
		return nil, fmt.Errorf("receiver setup: %w", err)
	}
	pt, err := opener.Open(s.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return pt, nil
}
