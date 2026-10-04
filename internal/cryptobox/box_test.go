package cryptobox

import (
	"bytes"
	"testing"
)

func TestEnvelopeBinding(t *testing.T) {
	key := Random(32)
	plain := []byte("credential")
	enc, e := Seal(key, plain, "device:a")
	if e != nil {
		t.Fatal(e)
	}
	got, e := Open(key, enc, "device:a")
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatal("round trip")
	}
	for _, purpose := range []string{"device:b", "token"} {
		if _, e = Open(key, enc, purpose); e == nil {
			t.Fatal("purpose confusion")
		}
	}
	enc[len(enc)-1] ^= 1
	if _, e = Open(key, enc, "device:a"); e == nil {
		t.Fatal("tampering accepted")
	}
	if _, e = Open(Random(32), enc, "device:a"); e == nil {
		t.Fatal("wrong key accepted")
	}
}
func TestTokens(t *testing.T) {
	s := Token()
	k, e := DecodeKey(s)
	if e != nil || len(k) != 32 {
		t.Fatal("invalid generated key")
	}
	if !Matches(Hash(s), s) || Matches(Hash(s), Token()) {
		t.Fatal("token comparison")
	}
	if _, e = DecodeKey("short"); e == nil {
		t.Fatal("weak key accepted")
	}
	Wipe(k)
	if !bytes.Equal(k, make([]byte, 32)) {
		t.Fatal("wipe")
	}
}
