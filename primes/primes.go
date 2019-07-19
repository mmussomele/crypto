package primes

import (
	"math/big"
	"math/bits"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

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
