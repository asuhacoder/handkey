package broker

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func TOTP(seed string, now time.Time) (string, error) {
	secret := seed
	period, digits := 30, 6
	var h func() hash.Hash = sha1.New
	bad := errors.New("invalid TOTP configuration")
	if strings.HasPrefix(seed, "otpauth://") {
		u, e := url.Parse(seed)
		if e != nil || u.Host != "totp" {
			return "", bad
		}
		q := u.Query()
		secret = q.Get("secret")
		if p := q.Get("period"); p != "" {
			period, e = strconv.Atoi(p)
			if e != nil || period < 1 || period > 3600 {
				return "", bad
			}
		}
		if d := q.Get("digits"); d != "" {
			digits, e = strconv.Atoi(d)
			if e != nil || (digits != 6 && digits != 8) {
				return "", bad
			}
		}
		switch strings.ToUpper(q.Get("algorithm")) {
		case "", "SHA1":
		case "SHA256":
			h = sha256.New
		case "SHA512":
			h = sha512.New
		default:
			return "", bad
		}
	}
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(strings.ToUpper(strings.ReplaceAll(secret, " ", "")), "="))
	if e != nil || len(key) == 0 {
		return "", bad
	}
	defer clear(key)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/int64(period)))
	mac := hmac.New(h, key)
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	n := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	mod := uint32(1000000)
	if digits == 8 {
		mod = 100000000
	}
	return fmt.Sprintf("%0*d", digits, n%mod), nil
}
