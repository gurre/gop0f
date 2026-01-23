package gop0f

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
)

// Ported from p0f/api.h
const (
	P0F_STATUS_BADQUERY = 0x00
	P0F_STATUS_OK       = 0x10
	P0F_STATUS_NOMATCH  = 0x20
	P0F_ADDR_IPV4       = 0x04
	P0F_ADDR_IPV6       = 0x06
	P0F_STR_MAX         = 31
	P0F_MATCH_FUZZY     = 0x01
	P0F_MATCH_GENERIC   = 0x02
)

var (
	P0F_QUERY_MAGIC = [...]byte{0x50, 0x30, 0x46, 0x1} //0x50304601
	P0F_RESP_MAGIC  = [...]byte{0x50, 0x30, 0x46, 0x2} //0x50304602
)

type GoP0f struct {
	conn   net.Conn
	socket string
}

type P0fQuery struct {
	Magic    [4]byte  // Must be P0F_QUERY_MAGIC
	AddrType byte     // P0F_ADDR_*
	Addr     [16]byte // IP address (big endian left align)
}

type P0fResponse struct {
	Magic      uint32                // Must be P0F_RESP_MAGIC
	Status     uint32                // P0F_STATUS_*
	FirstSeen  uint32                // First seen (unix time)
	LastSeen   uint32                // Last seen (unix time)
	TotalCount uint32                // Total connections seen
	UptimeMin  uint32                // Last uptime (minutes)
	UpModDays  uint32                // Uptime modulo (days)
	LastNat    uint32                // NAT / LB last detected (unix time)
	LastChg    uint32                // OS chg last detected (unix time)
	Distance   int16                 // System distance (-1 if unavailable)
	BadSw      byte                  // Host is lying about U-A / Server: 0=unknown, 1=OS mismatch, 2=outright mismatch
	OsMatchQ   byte                  // Match quality: 0=normal, 1=fuzzy, 2=generic, 3=both
	OsName     [P0F_STR_MAX + 1]byte // Name of detected OS
	OsFlavor   [P0F_STR_MAX + 1]byte // Flavor of detected OS
	HttpName   [P0F_STR_MAX + 1]byte // Name of detected HTTP app
	HttpFlavor [P0F_STR_MAX + 1]byte // Flavor of detected HTTP app
	LinkType   [P0F_STR_MAX + 1]byte // Link type
	Language   [P0F_STR_MAX + 1]byte // Language
}

func New(sock string) (p0f *GoP0f, err error) {
	if _, err = os.Stat(sock); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = errors.New("socket file does not exist: " + sock)
		}
		return
	}
	p0f = &GoP0f{
		socket: sock,
	}
	p0f.conn, err = net.Dial("unix", p0f.socket)
	if err != nil {
		return
	}

	return
}

func (p0f *GoP0f) Close() {
	p0f.conn.Close()
}

func (p0f *GoP0f) Query(addr net.IP) (resp P0fResponse, err error) {
	var querybuf bytes.Buffer
	binary.Write(&querybuf, binary.LittleEndian, newP0fQuery(addr))

	qq := querybuf.Bytes()
	_, err = p0f.conn.Write(qq)
	if err != nil {
		return
	}

	var n int
	readbuf := make([]byte, 1048)
	n, err = p0f.conn.Read(readbuf[:])
	if err != nil {
		return
	}
	buf := bytes.NewReader(readbuf[0:n])
	err = binary.Read(buf, binary.LittleEndian, &resp)
	return
}

func newP0fQuery(addr net.IP) *P0fQuery {
	q := &P0fQuery{
		Magic: P0F_QUERY_MAGIC,
	}
	if ip4 := addr.To4(); ip4 != nil {
		q.AddrType = P0F_ADDR_IPV4
		copy(q.Addr[:], ip4) // 4 bytes, left-aligned
	} else {
		q.AddrType = P0F_ADDR_IPV6
		copy(q.Addr[:], addr.To16()) // 16 bytes
	}
	return q
}
