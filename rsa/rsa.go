package rsa

import (
	"math/big"

	"github.com/mmussomele/crypto/primes"
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
	qBits := bits - p.BitLen()

	for {
		// TODO: This is very slow if we gen unlucky. Be cleverer about finding a
		// matching q.
		q, err = primes.Find(qBits, 128)
		if err != nil {
			return nil, nil, nil, err
		}

		n = new(big.Int).Mul(p, q)
		if n.BitLen() == bits {
			return p, q, n, nil
		}
	}
}
