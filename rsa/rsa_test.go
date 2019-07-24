package rsa

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/mmussomele/crypto/rand"
)

func TestEncryption(t *testing.T) {
	// Test powers of 2 up to 4096, plus some other numbers.
	var sizes []int
	for i := uint(6); i < 10; i++ {
		sizes = append(sizes, 1<<i)
	}

	sizes = append(sizes, 135, 431, 776, 1029, 1315, 1419, 1592, 1800, 1912)
	for _, size := range sizes {
		priv, err := NewKey(size)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		for i := 0; i < 10; i++ {
			max := big.NewInt(1)
			max.Lsh(max, uint(size-1))
			m, err := rand.Int(max)
			if err != nil {
				t.Fatalf("Failed to generate test message: %v", err)
			}

			c, err := encrypt(priv.PublicKey(), m)
			switch {
			case err != nil:
				t.Fatalf("Failed to encrypt test message: %v", err)
			case c.Cmp(m) == 0:
				t.Fatal("Encrypted message matched original")
			}

			d, err := decrypt(priv, c)
			switch {
			case err != nil:
				t.Fatalf("Failed to decrypt test message: %v", err)
			case d.Cmp(c) == 0:
				t.Fatal("Decrypted message matched encrypted message")
			case m.Cmp(d) != 0:
				t.Fatal("Decrypted message did not match original")
			}
		}
	}
}

func TestOAEP(t *testing.T) {
	h := sha256.New()

	// Test powers of 2 up to 4096, plus some other numbers.
	var sizes []int
	for i := uint(0); i < 13; i++ {
		sizes = append(sizes, 1<<i)
	}
	sizes = append(sizes, 3, 5, 7, 135, 431, 776, 1029, 1315, 1419, 1592, 1800, 1912)
	psizes := []int{4, 35, 23, 372, 512, 623}

	for _, size := range sizes {
		b := make([]byte, size)
		_, err := rand.Read(b)
		if err != nil {
			t.Fatalf("Failed to generate test message: %v", err)
		}
		for _, ps := range psizes {
			p := make([]byte, ps)
			_, err := rand.Read(p)
			if err != nil {
				t.Fatalf("Failed to generate test p: %v", err)
			}

			enc, err := oaepEncode(h, b, p, size+3*h.Size())
			switch {
			case err != nil:
				t.Fatalf("Failed to encode test message: %v", err)
			case bytes.Equal(enc, b):
				t.Fatal("Encoded message matched original")
			}

			dec, err := oaepDecode(h, enc, p)
			switch {
			case err != nil:
				t.Fatalf("Failed to decode test message: %v", err)
			case bytes.Equal(dec, enc):
				t.Fatal("Decoded message matched encoded message")
			case !bytes.Equal(b, dec):
				t.Fatal("Decoded message did not match original")
			}

			p[0]++
			dec, err = oaepDecode(h, enc, p)
			if err == nil {
				t.Fatal("Succeeded decoding with wrong p")
			}
		}
	}
}
