package broker

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238(t *testing.T) {
	for _, v := range []struct {
		at   int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		got, e := TOTP("otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8", time.Unix(v.at, 0))
		if e != nil || got != v.want {
			t.Fatalf("%d: %s %v", v.at, got, e)
		}
	}
}
func TestInvalidTOTP(t *testing.T) {
	for _, s := range []string{"not:a:seed", "otpauth://hotp/x?secret=ABC", "otpauth://totp/x?secret=ABC&period=0", "otpauth://totp/x?secret=ABC&digits=9", "otpauth://totp/x?secret=ABC&algorithm=MD5"} {
		if _, e := TOTP(s, time.Now()); e == nil {
			t.Fatal("accepted invalid seed")
		}
	}
}
func FuzzTOTP(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXP")
	f.Fuzz(func(t *testing.T, seed string) {
		out, e := TOTP(seed, time.Unix(100, 0))
		if e == nil && len(out) != 6 && len(out) != 8 {
			t.Fatal("invalid output")
		}
		if e != nil && strings.Contains(e.Error(), seed) && len(seed) > 10 {
			t.Fatal("seed leaked")
		}
	})
}
