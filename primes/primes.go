package primes

import (
	"math/big"
	"math/bits"

	"github.com/mmussomele/crypto/rand"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

// Find finds a random prime number of at least b bits. The probability that the
// returned number is not prime is at most 2^(-n).
func Find(b, n int) (*big.Int, error) {
	p := new(big.Int)
	buf := make([]byte, (b+7)/8)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	p.SetBytes(buf)
	if p.BitLen() < b {
		p.SetBit(p, b-1, 1) // Ensure p is at least b bits
	}
	return FindNext(p, n)
}

// FindNext finds the first prime number bigger than or equal to n. The probability that
// the returned number is not prime is at most 2^(-n).
func FindNext(s *big.Int, n int) (*big.Int, error) {
	s = new(big.Int).SetBit(s, 0, 1)
	for {
		switch ok, err := Is(s, n); {
		case err != nil:
			return nil, err
		case ok:
			return s, nil
		}
		s.Add(s, two)
	}
}

// FindPrevious finds the first prime number smaller than or equal to n. The probability
// that the returned number is not prime is at most 2^(-n).
func FindPrevious(s *big.Int, n int) (*big.Int, error) {
	s = new(big.Int).Set(s)
	if s.Bit(0) == 0 {
		s.Sub(s, one)
	}
	for {
		switch ok, err := Is(s, n); {
		case err != nil:
			return nil, err
		case ok:
			return s, nil
		}
		s.Sub(s, two)
	}
}

// Is performs a Solovay-Strassen primality test on p. The probability of a false
// positive is at most 2^(-n).
func Is(p *big.Int, n int) (bool, error) {
	p = new(big.Int).Set(p)
	limit := new(big.Int).Sub(p, two)

	// pow = (p-1)/2
	pow := new(big.Int).Set(p)
	pow.Sub(pow, one).Rsh(pow, 1)

	for i := 0; i < n; i++ {
		a, err := rand.Int(limit)
		if err != nil {
			return false, err
		}
		a.Add(a, two) // a is random in [2,p)

		j := Jacobi(a, p)
		if j == 0 {
			return false, nil
		}
		jm := big.NewInt(int64(j))
		jm.Mod(jm, p)

		// Check if a^((p-1)/2) == j (mod p)
		m := a.Exp(a, pow, p)
		if m.Cmp(jm) != 0 {
			return false, nil
		}
	}
	return true, nil
}

// Jacobi computes the Jacobi symbol of a and b.
func Jacobi(a, b *big.Int) int {
	a = new(big.Int).Set(a)
	b = new(big.Int).Set(b)

	var (
		s = 1
		c = new(big.Int)
	)

	for {
		if b.Cmp(one) == 0 || a.Cmp(one) == 0 {
			return s
		}
		// All computations for the Jacobi are done in the (mod b) space.
		a.Mod(a, b)
		if a.Cmp(zero) == 0 {
			return 0
		}

		i := trailingZeroes(a)
		c.Rsh(a, i)

		// a and b are now odd, positive and coprime. Law of Quadratic
		// Reciprocity applies.

		if i&1 == 1 {
			// J(2a,b) = -1 if b = 3 or 5 (mod 8)
			if m := b.Bits()[0] & 7; m == 3 || m == 5 {
				s = -s
			}
		}

		// J(c,b)J(b,c) = -1 if n = m = 3 (mod 4)
		n := c.Bits()[0] & 3
		m := b.Bits()[0] & 3
		if n == 3 && m == 3 {
			s = -s
		}

		a.Set(b)
		b.Set(c)
	}
}

// Find the number of trailing zeros in a to do one `n` shift instead of
// `n` one shifts.
func trailingZeroes(a *big.Int) uint {
	aw := a.Bits()

	var i int
	for i < len(aw) && aw[i] == 0 {
		i++
	}

	switch i {
	case len(aw):
		return uint(i * bits.UintSize)
	default:
		return uint(i*bits.UintSize + bits.TrailingZeros(uint(aw[i])))
	}
}
