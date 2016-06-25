package gop0f

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestInvalidUnixSocket(t *testing.T) {
	_, err := New(".")
	if err == nil {
		t.Errorf("An invalid unix socket does not return an error")
	}
}

func TestQueryLength(t *testing.T) {
	q := newP0fQuery(net.ParseIP("127.0.0.1"))

	var querybuf bytes.Buffer
	binary.Write(&querybuf, binary.BigEndian, q)

	qq := querybuf.Bytes()
	if len(qq) != 21 {
		t.Errorf("p0f query must have a length of 21. Was %d", len(qq))
	}

}
