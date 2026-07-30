package chain

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// encodeService is a faithful ABI encoding of the full Service tuple (statics +
// the five dynamic string fields), so tests can place a real url and confirm both
// the dynamic url decode and the static signer/ack decode survive around it.
func encodeService(provider, serviceType, url, model, verifiability, additionalInfo string,
	inputPrice, outputPrice, updatedAt uint64, signer string, ack bool) []byte {
	const word = 32
	u := func(n uint64) []byte { w := make([]byte, word); binary.BigEndian.PutUint64(w[24:], n); return w }
	addr := func(h string) []byte {
		w := make([]byte, word)
		b, _ := hex.DecodeString(strings.TrimPrefix(h, "0x"))
		copy(w[word-len(b):], b)
		return w
	}
	boolw := func(v bool) []byte {
		w := make([]byte, word)
		if v {
			w[word-1] = 1
		}
		return w
	}
	strTail := func(s string) []byte {
		b := []byte(s)
		t := u(uint64(len(b)))
		padded := (len(b) + word - 1) / word * word
		buf := make([]byte, padded)
		copy(buf, b)
		return append(t, buf...)
	}

	// Dynamic fields in Service index order: serviceType(1), url(2), model(6),
	// verifiability(7), additionalInfo(8).
	dyn := []string{serviceType, url, model, verifiability, additionalInfo}
	tails := make([][]byte, len(dyn))
	offsets := make([]uint64, len(dyn))
	cur := uint64(11 * word) // tails begin after the 11 head words
	for i, s := range dyn {
		tails[i] = strTail(s)
		offsets[i] = cur
		cur += uint64(len(tails[i]))
	}

	head := [][]byte{
		addr(provider), // 0
		u(offsets[0]),  // 1 serviceType
		u(offsets[1]),  // 2 url
		u(inputPrice),  // 3
		u(outputPrice), // 4
		u(updatedAt),   // 5
		u(offsets[2]),  // 6 model
		u(offsets[3]),  // 7 verifiability
		u(offsets[4]),  // 8 additionalInfo
		addr(signer),   // 9 teeSignerAddress
		boolw(ack),     // 10 teeSignerAcknowledged
	}

	out := u(32) // outer offset to the struct
	for _, w := range head {
		out = append(out, w...)
	}
	for _, t := range tails {
		out = append(out, t...)
	}
	return out
}

func TestDecodeServiceURL(t *testing.T) {
	const (
		url    = "https://provider.example.com/v1"
		signer = "0x1122334455667788990011223344556677889900"
	)
	raw := encodeService("0x00000000000000000000000000000000000000aa",
		"chatbot", url, "gpt-4o", "TEE", `{"x":1}`, 10, 20, 30, signer, true)

	gotURL, err := decodeServiceURL(raw)
	if err != nil {
		t.Fatalf("decodeServiceURL: %v", err)
	}
	if gotURL != url {
		t.Errorf("url = %q, want %q", gotURL, url)
	}

	// Static signer/ack must still decode correctly with real strings around them.
	gotSigner, ack, err := decodeService(raw)
	if err != nil {
		t.Fatalf("decodeService: %v", err)
	}
	if !strings.EqualFold(gotSigner, signer) || !ack {
		t.Errorf("got (%s, %v), want (%s, true)", gotSigner, ack, signer)
	}
}

func TestDecodeServiceURL_Empty(t *testing.T) {
	// buildServiceReturn (registry_test.go) encodes empty strings.
	url, err := decodeServiceURL(buildServiceReturn("0x00000000000000000000000000000000000000ff", true))
	if err != nil || url != "" {
		t.Errorf("empty url: got (%q, %v), want (\"\", nil)", url, err)
	}
}

func TestOnChainRegistry_ServiceInfo(t *testing.T) {
	const (
		provider = "0xaabbccddeeff00112233445566778899aabbccdd"
		signer   = "0x99887766554433221100ffeeddccbbaa99887766"
		url      = "https://prov.example/v1"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := encodeService(provider, "chatbot", url, "m", "TEE", "", 1, 2, 3, signer, true)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x` + hex.EncodeToString(raw) + `"}`))
	}))
	defer srv.Close()

	reg, err := NewOnChainRegistry(Config{RPCURL: srv.URL})
	if err != nil {
		t.Fatalf("NewOnChainRegistry: %v", err)
	}
	info, err := reg.ServiceInfo(context.Background(), provider)
	if err != nil {
		t.Fatalf("ServiceInfo: %v", err)
	}
	if info.URL != url {
		t.Errorf("URL = %q, want %q", info.URL, url)
	}
	if !strings.EqualFold(info.Signer, signer) || !info.Acknowledged {
		t.Errorf("got (%s, %v), want (%s, true)", info.Signer, info.Acknowledged, signer)
	}
}
