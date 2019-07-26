// Package rsa implements a subset of RFC 2437L PKCS #1 v2.0
// Notably it implements RSA encryption and decryption with OAEP.
package rsa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"

	"github.com/mmussomele/crypto/primes"
	"github.com/mmussomele/crypto/rand"
)

// PrivateKey is an RSA private key.
type PrivateKey struct {
	n    *big.Int
	e    *big.Int
	d    *big.Int
	p    *big.Int
	q    *big.Int
	dP   *big.Int
	dQ   *big.Int
	qInv *big.Int

	bits int
}

// PublicKey returns the public parameters of p.
func (p *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{
		n:    p.n,
		e:    p.e,
		bits: p.bits,
	}
}

// PublicKey is an RSA public key.
type PublicKey struct {
	n *big.Int
	e *big.Int

	bits int
}

// E is the chosen encryption exponent.
const E = (1 << 16) + 1

var (
	one = big.NewInt(1)
	e   = big.NewInt(E)
)

// NewKey generates a new RSA key pair of the requested number of bits. bits must be at
// least 8.
func NewKey(bits int) (*PrivateKey, error) {
	fail := func(err error) (*PrivateKey, error) { return nil, err }

	if bits < 64 {
		panic("crypto/rsa: bits must be at least 64")
	}

	for {
		p, q, n, err := genSecrets(bits)
		if err != nil {
			return fail(err)
		}

		// Compute lcd = lambda(n)
		p1 := new(big.Int).Sub(p, one)
		q1 := new(big.Int).Sub(q, one)
		p1q1 := new(big.Int).Mul(p1, q1)
		gcd := new(big.Int).GCD(nil, nil, p1, q1)
		lcd := new(big.Int).Div(p1q1, gcd)

		// (_ * lcd) + (d * e) = 1 (mod lcd) => de = 1 (mod lcd)
		d := new(big.Int)
		gcd = new(big.Int).GCD(nil, d, lcd, e)
		if gcd.Cmp(one) != 0 {
			continue // gcd(e, lambda(n)) != 1, try new modulus
		}

		dP := new(big.Int).Mod(d, p1)
		dQ := new(big.Int).Mod(d, q1)
		qInv := new(big.Int).ModInverse(q, p)

		priv := &PrivateKey{
			n:    n,
			e:    new(big.Int).Set(e),
			d:    d,
			p:    p,
			q:    q,
			dP:   dP,
			dQ:   dQ,
			qInv: qInv,
			bits: bits,
		}

		return priv, nil
	}
}

// Generic error messages.
var (
	ErrMessageTooLarge       = errors.New("crypto/rsa: message too large")
	ErrCipherTextWrongLength = errors.New("crypto/rsa: cipher text wrong length")
	ErrDecryption            = errors.New("crypto/rsa: decryption failure")
	ErrEncoding              = errors.New("crypto/rsa: encoding failure")
	ErrDecoding              = errors.New("crypto/rsa: decoding failure")
)

// Encrypt encrypts m using the public key and masking (defined by h). p must be the
// same value passed to Decrypt.
func Encrypt(pub *PublicKey, h hash.Hash, m, p []byte) ([]byte, error) {
	keySize := (pub.bits + 7) / 8
	if len(m) > keySize-2*h.Size()-2 {
		return nil, ErrMessageTooLarge
	}
	em, err := oaepEncode(h, m, p, keySize-1)
	if err != nil {
		return nil, err
	}
	c, err := encrypt(pub, new(big.Int).SetBytes(em))
	if err != nil {
		return nil, err
	}
	cb := c.Bytes()
	if len(cb) < keySize {
		pad := make([]byte, keySize-len(cb))
		cb = append(pad, cb...)
	}
	return cb, nil
}

func encrypt(p *PublicKey, m *big.Int) (*big.Int, error) {
	return new(big.Int).Exp(m, p.e, p.n), nil
}

// Decrypt decrypts c using the private key and masking (defined by h). p must be the
// same value passed to Encrypt.
func Decrypt(priv *PrivateKey, h hash.Hash, c, p []byte) ([]byte, error) {
	keySize := (priv.bits + 7) / 8
	if len(c) != keySize {
		return nil, ErrCipherTextWrongLength
	}

	// Use blinding to stop timing attacks. Multiplying c by r^e gives
	// c(r^e)=(m^e)(r^e) (mod n). ((m^e)(r^e))^d=m*r => m*r*rInv=m (mod n)
	// Note: r must be coprime with N
	var err error
	var r, rInv *big.Int
	for rInv == nil {
		r, err = rand.Int(priv.n)
		if err != nil {
			return nil, ErrDecryption
		}

		rInv = new(big.Int).ModInverse(r, priv.n)
	}
	r.Exp(r, priv.e, priv.n)

	bc := new(big.Int).SetBytes(c)
	bc.Mul(bc, r).Mod(bc, priv.n)

	bm := decrypt(priv, bc)
	bm.Mul(bm, rInv).Mod(bm, priv.n)

	em := bm.Bytes()
	if len(em) < keySize-1 {
		pad := make([]byte, keySize-len(em)-1)
		em = append(pad, em...)
	}
	m, err := oaepDecode(h, em, p)
	if err != nil {
		return nil, ErrDecryption
	}
	return m, nil
}

func decrypt(p *PrivateKey, c *big.Int) *big.Int {
	m1 := new(big.Int).Exp(c, p.dP, p.p)
	m2 := new(big.Int).Exp(c, p.dQ, p.q)

	// h = m2+ q * (qInv (m1-m2) (mod p))
	h := new(big.Int).Sub(m1, m2)
	h.Mul(h, p.qInv)
	h.Mod(h, p.p)
	h.Mul(h, p.q)
	h.Add(h, m2)
	return h
}

func oaepEncode(h hash.Hash, m, p []byte, l int) ([]byte, error) {
	if len(m) > l-2*h.Size()-1 {
		return nil, ErrEncoding
	}

	padLen := l - len(m) - 2*h.Size() - 1

	var ps []byte
	if padLen > 0 {
		ps = make([]byte, padLen)
	}

	h.Reset()
	h.Write(p)
	db := h.Sum(nil)
	db = append(db, ps...)
	db = append(db, 1)
	db = append(db, m...)

	s := make([]byte, h.Size())
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}

	dbm := mgf(h, s, l-h.Size())
	mustSameLength(db, dbm)
	for i := range db {
		db[i] ^= dbm[i]
	}

	sm := mgf(h, db, h.Size())
	mustSameLength(s, sm)
	for i := range s {
		s[i] ^= sm[i]
	}

	return append(s, db...), nil
}

func oaepDecode(h hash.Hash, em, p []byte) ([]byte, error) {
	if len(em) < 2*h.Size()+1 {
		return nil, ErrDecoding
	}

	s, db := em[:h.Size()], em[h.Size():]

	sm := mgf(h, db, h.Size())
	mustSameLength(s, sm)
	for i := range s {
		s[i] ^= sm[i]
	}

	dbm := mgf(h, s, len(em)-h.Size())
	mustSameLength(db, dbm)
	for i := range db {
		db[i] ^= dbm[i]
	}

	h.Reset()
	h.Write(p)
	ps := h.Sum(nil)

	if !bytes.HasPrefix(db, ps) {
		return nil, ErrDecoding
	}

	db = bytes.TrimPrefix(db, ps)
	db = bytes.TrimLeft(db, "\x00")
	if len(db) == 0 || db[0] != 1 {
		return nil, ErrDecoding
	}
	return db[1:], nil
}

func mustSameLength(a, b []byte) {
	if len(a) != len(b) {
		panic("length mismatch")
	}
}

func mgf(h hash.Hash, z []byte, l int) []byte {
	t := make([]byte, 0, l)

	// n = ceil(l/h.Size())
	n := uint32(l / h.Size())
	if l%h.Size() != 0 {
		n++
	}

	b := make([]byte, 4)
	for i := uint32(0); i < n; i++ {
		binary.BigEndian.PutUint32(b, i)
		h.Reset()
		h.Write(z)
		h.Write(b)
		t = h.Sum(t)
	}

	return t[:l]
}

// Generate two large primes p and q such that pq has exactly the required bits.
func genSecrets(bits int) (p, q, n *big.Int, err error) {
	// Key is more secure if p and q differ slightly in bit length
	p, err = primes.Find(bits/2+1, 128)
	if err != nil {
		return nil, nil, nil, err
	}

	// In order for n to have the desired number of bits, q must fit within the range
	// l=2^(bits-1)/p to u=2^bits/p. The range of those values is
	// (u-l)/p = 2^(bits-1)/p = l/p.
	// Therefore, a valid q is found by choosing a random number l/p+rand.Int(l/p), then
	// selecting a nearby prime.
	qMin := new(big.Int).Lsh(one, uint(bits-1))
	qMin.Div(qMin, p)

	qn, err := rand.Int(qMin)
	if err != nil {
		return nil, nil, nil, err
	}
	qn.Add(qn, qMin)

	q, err = primes.FindNext(qn, 128)
	if err != nil {
		return nil, nil, nil, err
	}

	n = new(big.Int).Mul(p, q)
	switch nb := n.BitLen(); {
	case nb == bits:
		return p, q, n, nil
	case nb < bits:
		panic(nb) // should be impossible
	}

	// qn was too close to the upper bound and n was too large. Use the previous
	// prime instead.
	q, err = primes.FindPrevious(qn, 128)
	if err != nil {
		return nil, nil, nil, err
	}

	n.Mul(p, q)
	return p, q, n, nil
}
