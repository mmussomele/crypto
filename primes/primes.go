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
		d = new(big.Int)
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
		a.Rsh(a, i)

		// Instead of computing a new value for s for each shift, only do it once
		// if i is odd, since (-1)^2 == 1.
		if i&1 == 1 {
			// a is even, s *= (-1)^((b^2-1)/8)
			c.Set(b).Mul(c, c).Sub(c, one).Rsh(c, 3)
			if c.Bit(0) == 1 {
				s = -s
			}
		}

		// a is odd, s *= (-1)^((a-1)(b-1)/4)
		c.Set(a).Sub(c, one)
		d.Set(b).Sub(d, one)
		c.Mul(c, d).Rsh(c, 2)
		if c.Bit(0) == 1 {
			s = -s
		}

		// a = b % a, b = a
		c.Mod(b, a)
		b.Set(a)
		a.Set(c)
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
