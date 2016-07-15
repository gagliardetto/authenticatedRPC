package authenticatedRPC

import (
	"testing"
)

type testpair struct {
	in  []byte
	out []byte
}

var tests = []testpair{
	{in: []byte("something in"), out: []byte("something out")},
}

func TestSomething(t *testing.T) {
	t.Skip()
}
