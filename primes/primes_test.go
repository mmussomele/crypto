package primes

import (
	"math/big"
	"math/rand"
	"testing"
	"time"
)

const iters = 500

func TestJacobi(t *testing.T) {
	for i := int64(0); i < 500; i++ {
		for j := int64(1); j < 500; j += 2 {
			assertJacobi(t, big.NewInt(i), big.NewInt(j))
		}
	}
}

var (
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func TestJacobiLarge(t *testing.T) {
	for n := 0; n < 500; n++ {
		i, j := randInputs(384)
		assertJacobi(t, i, j)
	}
}

func assertJacobi(t *testing.T, i, j *big.Int) {
	actual := Jacobi(new(big.Int).Set(i), new(big.Int).Set(j))
	exp := big.Jacobi(new(big.Int).Set(i), new(big.Int).Set(j))
	if actual != exp {
		t.Fatalf("Expected, J(%d, %d) = %d, got %d", i, j, exp, actual)
	}
}

func BenchmarkJacobi2(b *testing.B) {
	i, j := randInputs(2)
	benchmarkJacobi(i, j, b)
}

func BenchmarkJacobi16(b *testing.B) {
	i, j := randInputs(16)
	benchmarkJacobi(i, j, b)
}

func BenchmarkJacobi32(b *testing.B) {
	i, j := randInputs(32)
	benchmarkJacobi(i, j, b)
}

func BenchmarkJacobi64(b *testing.B) {
	i, j := randInputs(64)
	benchmarkJacobi(i, j, b)
}

func BenchmarkJacobi128(b *testing.B) {
	i, j := randInputs(128)
	benchmarkJacobi(i, j, b)
}

func BenchmarkJacobi256(b *testing.B) {
	i, j := randInputs(256)
	benchmarkJacobi(i, j, b)
}

func BenchmarkJacobi512(b *testing.B) {
	i, j := randInputs(512)
	benchmarkJacobi(i, j, b)
}

func benchmarkJacobi(a, b *big.Int, tb *testing.B) {
	for i := 0; i < tb.N; i++ {
		Jacobi(a, b)
	}
}

func BenchmarkStdlibJacobi2(b *testing.B) {
	i, j := randInputs(2)
	benchmarkStdlibJacobi(i, j, b)
}

func BenchmarkStdlibJacobi16(b *testing.B) {
	i, j := randInputs(16)
	benchmarkStdlibJacobi(i, j, b)
}

func BenchmarkStdlibJacobi32(b *testing.B) {
	i, j := randInputs(32)
	benchmarkStdlibJacobi(i, j, b)
}

func BenchmarkStdlibJacobi64(b *testing.B) {
	i, j := randInputs(64)
	benchmarkStdlibJacobi(i, j, b)
}

func BenchmarkStdlibJacobi128(b *testing.B) {
	i, j := randInputs(128)
	benchmarkStdlibJacobi(i, j, b)
}

func BenchmarkStdlibJacobi256(b *testing.B) {
	i, j := randInputs(256)
	benchmarkStdlibJacobi(i, j, b)
}

func BenchmarkStdlibJacobi512(b *testing.B) {
	i, j := randInputs(512)
	benchmarkStdlibJacobi(i, j, b)
}

func benchmarkStdlibJacobi(a, b *big.Int, tb *testing.B) {
	for i := 0; i < tb.N; i++ {
		big.Jacobi(a, b)
	}
}

func randInputs(bits uint) (a, b *big.Int) {
	max := new(big.Int).Lsh(big.NewInt(1), bits)
	a = new(big.Int).Rand(r, max)
	b = new(big.Int).Rand(r, max)
	if b.Bit(0) == 0 {
		b.Add(b, one)
	}
	return a, b
}
