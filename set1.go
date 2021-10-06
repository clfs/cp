package cp

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
	"os"
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

func XORCycle(a []byte, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i%len(b)]
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

func init() {
	RuneFrequencies = make(map[rune]float64)
	data, err := os.ReadFile("misc/english.txt")
	if err != nil {
		panic(err)
	}
	for _, r := range string(data) {
		RuneFrequencies[r]++
	}
	scale := float64(len(data))
	for k, v := range RuneFrequencies {
		RuneFrequencies[k] = v / scale
	}
}

var RuneFrequencies map[rune]float64

func ScoreEnglish(s string) float64 {
	var score float64
	for _, r := range s {
		if _, ok := RuneFrequencies[r]; ok {
			score += RuneFrequencies[r]
		}
	}
	return score
}

func DetectSingleXOR(cts [][]byte) []byte {
	var best []byte
	var maxScore float64
	for _, ct := range cts {
		key := FindXORKey(ct)
		pt := XORRepeat(ct, key)
		score := ScoreEnglish(string(pt))
		if score > maxScore {
			maxScore = score
			best = ct
		}
	}
	return best
}

func Hamming(a, b []byte) int {
	if len(a) != len(b) {
		panic("different lengths")
	}
	var d int
	for i := range a {
		d += bits.OnesCount(uint(a[i] ^ b[i]))
	}
	return d
}

func BreakRepeatingKeyXOR(ct []byte) []byte {
	var bestKeySize int
	bestKeySizeScore := math.MaxFloat64
	for keySize := 2; keySize <= 40; keySize++ {
		a, b := ct[:keySize*4], ct[keySize*4:keySize*8]
		score := float64(Hamming(a, b)) / float64(keySize)
		if score < bestKeySizeScore {
			bestKeySizeScore = score
			bestKeySize = keySize
		}
	}
	chunkSize := (len(ct) + bestKeySize - 1) / bestKeySize

	var (
		key   = make([]byte, bestKeySize)
		chunk = make([]byte, chunkSize)
	)

	for i := range key {
		for j := range chunk {
			if k := j*bestKeySize + i; k < len(ct) {
				chunk[j] = ct[k]
			}
		}
		key[i] = FindXORKey(chunk)
	}

	return key
}

type ecbDecrypter struct {
	cipher.Block
}

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return ecbDecrypter{b}
}

func (e ecbDecrypter) BlockSize() int {
	return e.Block.BlockSize()
}

func (e ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.BlockSize() != 0 || len(dst) < len(src) {
		panic("invalid length(s)")
	}
	b := e.BlockSize()
	for len(src) > 0 {
		e.Decrypt(dst, src)
		src = src[b:]
		dst = dst[b:]
	}
}
