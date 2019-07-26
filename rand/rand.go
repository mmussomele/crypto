package rand

import (
	"io"
	"math/big"
	"os"
	"sync"
)

const urandom = "/dev/urandom"

type reader struct {
	sync.Mutex

	src io.Reader
}

func (r *reader) Read(b []byte) (n int, err error) {
	r.Lock()
	defer r.Unlock()
	if r.src == nil {
		r.src, err = os.Open(urandom)
		if err != nil {
			return 0, err
		}
	}
	return io.ReadFull(r.src, b)
}

var r = new(reader)

// Read fills b with random bytes.
func Read(b []byte) (n int, err error) {
	return io.ReadFull(r, b)
}

// Reader returns a new cryptographically secure random source.
func Reader() io.Reader {
	return new(reader)
}

var one = big.NewInt(1)

func Int(max *big.Int) (*big.Int, error) {
	n := new(big.Int).Sub(max, one).BitLen()
	buf := make([]byte, (n+7)/8)

	candidate := new(big.Int)
	for {
		if _, err := Read(buf); err != nil {
			return nil, err
		}
		candidate.SetBytes(buf)

		// If the candidate has more bits than the allowed max, clear them.
		c := candidate.BitLen()
		for i := n; i < c; i++ {
			candidate.SetBit(candidate, i, 0)
		}

		if candidate.Cmp(max) < 0 {
			return candidate, nil
		}
	}
}
