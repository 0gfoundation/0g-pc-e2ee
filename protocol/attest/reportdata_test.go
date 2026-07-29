package attest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// makeReportData assembles a 64-byte report_data from its §4.2 fields, so tests
// build fixed vectors (KATs) and mutate one field at a time.
func makeReportData(encPub [encPubLen]byte, signer [signerLen]byte, version uint32, reserved [reservedLen]byte) []byte {
	rd := make([]byte, reportDataLen)
	copy(rd[encPubOff:], encPub[:])
	copy(rd[signerOff:], signer[:])
	binary.BigEndian.PutUint32(rd[versionOff:], version)
	copy(rd[reservedOff:], reserved[:])
	return rd
}

// sample fields reused across tests.
func sampleEncPub() [encPubLen]byte {
	var k [encPubLen]byte
	for i := range k {
		k[i] = byte(i + 1) // 0x01..0x20, distinct and nonzero
	}
	return k
}

func sampleSigner() [signerLen]byte {
	// 0xdeadbeef… pattern, 20 bytes.
	return [signerLen]byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
}

func TestParseReportData_Valid(t *testing.T) {
	encPub := sampleEncPub()
	signer := sampleSigner()
	rd, err := ParseReportData(makeReportData(encPub, signer, ReportDataVersion, [reservedLen]byte{}))
	if err != nil {
		t.Fatalf("ParseReportData: unexpected error: %v", err)
	}
	if !bytes.Equal(rd.EncPub, encPub[:]) {
		t.Errorf("EncPub = %x, want %x", rd.EncPub, encPub[:])
	}
	const wantSigner = "0xdeadbeef00112233445566778899aabbccddeeff"
	if rd.SignerAddr != wantSigner {
		t.Errorf("SignerAddr = %q, want %q", rd.SignerAddr, wantSigner)
	}
	if rd.Version != ReportDataVersion {
		t.Errorf("Version = %d, want %d", rd.Version, ReportDataVersion)
	}
}

func TestParseReportData_DoesNotAliasInput(t *testing.T) {
	encPub := sampleEncPub()
	raw := makeReportData(encPub, sampleSigner(), ReportDataVersion, [reservedLen]byte{})
	rd, err := ParseReportData(raw)
	if err != nil {
		t.Fatalf("ParseReportData: %v", err)
	}
	// Mutating the source buffer must not change the returned key.
	raw[encPubOff] ^= 0xff
	if !bytes.Equal(rd.EncPub, encPub[:]) {
		t.Errorf("EncPub aliases input buffer: got %x after mutation", rd.EncPub)
	}
}

func TestParseReportData_BadLength(t *testing.T) {
	for _, n := range []int{0, reportDataLen - 1, reportDataLen + 1} {
		if _, err := ParseReportData(make([]byte, n)); !errors.Is(err, ErrMalformedReportData) {
			t.Errorf("len %d: err = %v, want ErrMalformedReportData", n, err)
		}
	}
}

func TestParseReportData_BadVersion(t *testing.T) {
	raw := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion+1, [reservedLen]byte{})
	if _, err := ParseReportData(raw); !errors.Is(err, ErrMalformedReportData) {
		t.Errorf("err = %v, want ErrMalformedReportData", err)
	}
}

func TestParseReportData_ReservedNonzero(t *testing.T) {
	reserved := [reservedLen]byte{}
	reserved[reservedLen-1] = 1
	raw := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion, reserved)
	if _, err := ParseReportData(raw); !errors.Is(err, ErrMalformedReportData) {
		t.Errorf("err = %v, want ErrMalformedReportData", err)
	}
}
