package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// HPKE cipher suite (RFC 9180), base mode (anonymous sender):
//
//	KEM   DHKEM(X25519, HKDF-SHA256)   0x0020
//	KDF   HKDF-SHA256                  0x0001
//	AEAD  ChaCha20-Poly1305            0x0003
//
// This is the single source of truth for the suite. Any non-Go implementation
// (TS/WASM, Rust) MUST use the same suite to interoperate. The HPKE `info`
// string is NOT fixed here: it is a caller parameter, because different usages
// bind different contexts (SPEC §5.2/§6 use "0g-pc/v1/seal" for requests,
// §7 uses "0g-pc/v1/resp" for responses).
var (
	kemID  = hpke.KEM_X25519_HKDF_SHA256
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_ChaCha20Poly1305
)

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
// to open it. Convenience container for the one-shot Seal/Open below.
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

// Sealer encrypts messages under an HPKE context set up for one recipient.
type Sealer struct{ inner hpke.Sealer }

// Seal encrypts plaintext, authenticating aad (associated data) without
// encrypting it. Bind context that must be readable-but-tamper-evident (e.g. the
// cleartext envelope fields) as aad; Open fails if aad differs.
func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	ct, err := s.inner.Seal(plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return ct, nil
}

// Opener decrypts messages sealed to the recipient's key.
type Opener struct{ inner hpke.Opener }

// Open decrypts ciphertext, requiring aad to be byte-identical to what Seal was
// given. Any difference (tampered aad, flipped ciphertext, wrong key) fails
// rather than returning altered plaintext.
func (o *Opener) Open(ciphertext, aad []byte) ([]byte, error) {
	pt, err := o.inner.Open(ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return pt, nil
}

// SetupSender starts an HPKE send context to pub and returns the encapsulated
// key (enc) together with a Sealer. enc is produced BEFORE any Seal call, so a
// caller that must bind enc into its AAD (as the request envelope does — enc
// lives inside the AEAD-protected `_e2ee`) can obtain it first, build the AAD,
// then Seal. info domain-separates the usage (see the suite comment).
func SetupSender(pub PublicKey, info []byte) (enc []byte, s *Sealer, err error) {
	pk, err := kemScheme().UnmarshalBinaryPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("bad recipient public key: %w", err)
	}
	sender, err := suite().NewSender(pk, info)
	if err != nil {
		return nil, nil, fmt.Errorf("new sender: %w", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sender setup: %w", err)
	}
	return enc, &Sealer{inner: sealer}, nil
}

// SetupReceiver reconstructs the HPKE receive context from the recipient's
// private key and the sender's enc. info must match the sender's.
func SetupReceiver(priv PrivateKey, enc, info []byte) (*Opener, error) {
	sk, err := kemScheme().UnmarshalBinaryPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("bad recipient private key: %w", err)
	}
	receiver, err := suite().NewReceiver(sk, info)
	if err != nil {
		return nil, fmt.Errorf("new receiver: %w", err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("receiver setup: %w", err)
	}
	return &Opener{inner: opener}, nil
}

// Seal is the one-shot form for a single message whose aad does NOT depend on
// the encapsulated key: it sets up a sender, seals once, and returns enc +
// ciphertext together. When aad must include enc, use SetupSender instead.
func Seal(pub PublicKey, plaintext, aad, info []byte) (Sealed, error) {
	enc, s, err := SetupSender(pub, info)
	if err != nil {
		return Sealed{}, err
	}
	ct, err := s.Seal(plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Enc: enc, Ciphertext: ct}, nil
}

// Open is the one-shot counterpart to Seal.
func Open(priv PrivateKey, s Sealed, aad, info []byte) ([]byte, error) {
	o, err := SetupReceiver(priv, s.Enc, info)
	if err != nil {
		return nil, err
	}
	return o.Open(s.Ciphertext, aad)
}
