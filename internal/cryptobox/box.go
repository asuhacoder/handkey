// Package cryptobox implements purpose-bound AES-256-GCM envelopes.
package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

var ErrKey = errors.New("invalid key or encrypted envelope")

func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func Token() string { return base64.RawURLEncoding.EncodeToString(Random(32)) }
func DecodeKey(s string) ([]byte, error) {
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return nil, ErrKey
	}
	return b, nil
}
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func Matches(hash, token string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(Hash(token))) == 1
}
func Wipe(b []byte) { clear(b) }
func Seal(key, plaintext []byte, purpose string) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrKey
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrKey
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, ErrKey
	}
	nonce := Random(g.NonceSize())
	return g.Seal(nonce, nonce, plaintext, []byte(purpose)), nil
}
func Open(key, data []byte, purpose string) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrKey
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrKey
	}
	g, e := cipher.NewGCM(block)
	if e != nil || len(data) < g.NonceSize() {
		return nil, ErrKey
	}
	out, e := g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], []byte(purpose))
	if e != nil {
		return nil, ErrKey
	}
	return out, nil
}
