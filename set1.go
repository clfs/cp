package cp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func HexToBase64(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func HexXOR(a, b string) (string, error) {
	if len(a) != len(b) {
		return "", fmt.Errorf("different lengths")
	}
	ba, err := hex.DecodeString(a)
	if err != nil {
		return "", err
	}
	bb, err := hex.DecodeString(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(XOR(ba, bb)), nil
}

func XOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("different lengths")
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func XORRepeat(a []byte, b byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b
	}
	return out
}

func FindXORKey(ct []byte) byte {
	scores := make([]float64, 256)
	for i := 0; i < 256; i++ {
		pt := XORRepeat(ct, byte(i))
		scores[i] = ScoreEnglish(string(pt))
	}
	var max float64
	var bestKey byte
	for i, s := range scores {
		if s > max {
			max = s
			bestKey = byte(i)
		}
	}
	return bestKey
}

func ScoreEnglish(s string) float64 {
	var score float64
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			score += 1.0
		} else if c >= 'A' && c <= 'Z' {
			score += 0.5
		} else if c >= '0' && c <= '9' {
			score += 0.25
		}
	}
	return score
}
