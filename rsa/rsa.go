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
}

// PublicKey is an RSA public key.
type PublicKey struct {
	n *big.Int
	e int64
}

// E is the chosen encryption exponent.
const E = (1 << 16) + 1

var (
	one = big.NewInt(1)
	e   = big.NewInt(E)
)

// NewKey generates a new RSA key pair of the requested number of bits. bits must be at
// least 8.
func NewKey(bits int) (PrivateKey, PublicKey, error) {
	fail := func(err error) (PrivateKey, PublicKey, error) { return PrivateKey{}, PublicKey{}, err }

	if bits < 8 {
		panic("crypto/rsa: bits must be at least 8")
	}

	var (
		p1   = new(big.Int)
		q1   = new(big.Int)
		p1q1 = new(big.Int)

		gcd = new(big.Int)
		lcd = new(big.Int)

		d = new(big.Int)
	)

	for {
		p, q, n, err := genSecrets(bits)
		if err != nil {
			return fail(err)
		}

		// Compute lcd = lambda(n)
		p1.Sub(p, one)
		q1.Sub(q, one)
		p1q1.Mul(p1, q1)
		gcd.GCD(nil, nil, p1, q1)
		lcd = p1q1.Div(p1q1, gcd)

		// (_ * lcd) + (d * e) = 1 (mod lcd) => de = 1 (mod lcd)
		gcd.GCD(nil, d, lcd, e)
		if gcd.Cmp(one) != 0 {
			continue // gcd(e, lambda(n)) != 1, try new modulus
		}

		dP := new(big.Int).Mod(d, p1)
		dQ := new(big.Int).Mod(d, q1)
		qInv := new(big.Int).ModInverse(q, p)

		priv := PrivateKey{
			n:    n,
			e:    e,
			d:    d.Mod(d, n),
			p:    p,
			q:    q,
			dP:   dP,
			dQ:   dQ,
			qInv: qInv,
		}
		pub := PublicKey{n: n, e: E}

		return priv, pub, nil
	}
}

// Generic error messages.
var (
	ErrMessageTooLarge = errors.New("crypto/rsa: message too large")

	ErrEncodingFailed = errors.New("crypto/rsa: encoding failure")
	ErrDecodingFailed = errors.New("crypto/rsa: decoding failure")
)

func oaepEncode(h hash.Hash, m, p []byte, l int) ([]byte, error) {
	if len(m) > l-2*h.Size()-1 {
		return nil, ErrEncodingFailed
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
		return nil, ErrDecodingFailed
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
		return nil, ErrDecodingFailed
	}

	db = bytes.TrimPrefix(db, ps)
	db = bytes.TrimLeft(db, "\x00")
	if len(db) == 0 || db[0] != 1 {
		return nil, ErrDecodingFailed
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
