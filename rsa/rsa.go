package rsa

import (
	"math/big"

	"github.com/mmussomele/crypto/primes"
	"github.com/mmussomele/crypto/rand"
)

// PrivateKey is an RSA private key.
type PrivateKey struct {
	d *big.Int
}

// PublicKey is an RSA public key.
type PublicKey struct {
	mod *big.Int
	e   int64
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

		return PrivateKey{d: d.Mod(d, n)}, PublicKey{mod: n, e: E}, nil
	}
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
