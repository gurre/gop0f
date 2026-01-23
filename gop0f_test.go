package gop0f

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestInvalidUnixSocket(t *testing.T) {
	_, err := New(".")
	if err == nil {
		t.Errorf("An invalid unix socket does not return an error")
	}
}

func TestNonExistentSocket(t *testing.T) {
	_, err := New("/nonexistent/path/to/socket")
	if err == nil {
		t.Error("Expected error for non-existent socket")
	}
}

func TestQueryLength(t *testing.T) {
	q := newP0fQuery(net.ParseIP("127.0.0.1"))

	var querybuf bytes.Buffer
	binary.Write(&querybuf, binary.LittleEndian, q)

	qq := querybuf.Bytes()
	if len(qq) != 21 {
		t.Errorf("p0f query must have a length of 21. Was %d", len(qq))
	}
}

func TestQueryMagicBytes(t *testing.T) {
	q := newP0fQuery(net.ParseIP("127.0.0.1"))

	expected := [4]byte{0x50, 0x30, 0x46, 0x01}
	if q.Magic != expected {
		t.Errorf("Query magic bytes incorrect. Got %v, want %v", q.Magic, expected)
	}
}

func TestQueryIPv4Format(t *testing.T) {
	q := newP0fQuery(net.ParseIP("192.168.1.100"))

	if q.AddrType != P0F_ADDR_IPV4 {
		t.Errorf("AddrType should be IPv4 (0x04). Got 0x%02x", q.AddrType)
	}

	// IPv4 should be left-aligned: 192.168.1.100 followed by zeros
	expectedAddr := [16]byte{192, 168, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if q.Addr != expectedAddr {
		t.Errorf("IPv4 address not left-aligned correctly. Got %v, want %v", q.Addr, expectedAddr)
	}
}

func TestQueryIPv6Format(t *testing.T) {
	q := newP0fQuery(net.ParseIP("2001:db8::1"))

	if q.AddrType != P0F_ADDR_IPV6 {
		t.Errorf("AddrType should be IPv6 (0x06). Got 0x%02x", q.AddrType)
	}

	// Full IPv6 address should fill all 16 bytes
	expected := net.ParseIP("2001:db8::1").To16()
	if !bytes.Equal(q.Addr[:], expected) {
		t.Errorf("IPv6 address incorrect. Got %v, want %v", q.Addr[:], expected)
	}
}

func TestQueryIPv4MappedIPv6(t *testing.T) {
	// ::ffff:192.168.1.1 is IPv4-mapped IPv6, should be treated as IPv4
	q := newP0fQuery(net.ParseIP("::ffff:192.168.1.1"))

	if q.AddrType != P0F_ADDR_IPV4 {
		t.Errorf("IPv4-mapped IPv6 should be treated as IPv4. Got 0x%02x", q.AddrType)
	}

	expectedAddr := [16]byte{192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if q.Addr != expectedAddr {
		t.Errorf("IPv4-mapped address incorrect. Got %v, want %v", q.Addr, expectedAddr)
	}
}

func TestQueryLengthProperty(t *testing.T) {
	testCases := []string{
		"0.0.0.0",
		"127.0.0.1",
		"255.255.255.255",
		"192.168.1.1",
		"10.0.0.1",
		"::1",
		"2001:db8::1",
		"fe80::1",
		"::ffff:192.168.1.1",
	}

	for _, ip := range testCases {
		t.Run(ip, func(t *testing.T) {
			q := newP0fQuery(net.ParseIP(ip))
			var buf bytes.Buffer
			binary.Write(&buf, binary.LittleEndian, q)
			if buf.Len() != 21 {
				t.Errorf("Query length for %s should be 21, got %d", ip, buf.Len())
			}
		})
	}
}

func TestResponseSize(t *testing.T) {
	// p0f response: 9*uint32 (36) + int16 (2) + 2*byte (2) + 6*32byte strings (192) = 232 bytes
	var resp P0fResponse
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, &resp)

	expectedSize := 232
	if buf.Len() != expectedSize {
		t.Errorf("Response struct size should be %d bytes, got %d", expectedSize, buf.Len())
	}
}

func TestParseResponseOK(t *testing.T) {
	// Build a mock response with status OK
	resp := buildMockResponse(P0F_STATUS_OK, "Linux", "3.x", "Ethernet")

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, &resp)

	var parsed P0fResponse
	err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &parsed)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if parsed.Status != P0F_STATUS_OK {
		t.Errorf("Status should be OK (0x10), got 0x%02x", parsed.Status)
	}

	osName := bytesToString(parsed.OsName[:])
	if osName != "Linux" {
		t.Errorf("OsName should be 'Linux', got '%s'", osName)
	}
}

func TestParseResponseNoMatch(t *testing.T) {
	resp := buildMockResponse(P0F_STATUS_NOMATCH, "", "", "")

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, &resp)

	var parsed P0fResponse
	err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &parsed)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if parsed.Status != P0F_STATUS_NOMATCH {
		t.Errorf("Status should be NOMATCH (0x20), got 0x%02x", parsed.Status)
	}
}

func TestParseResponseBadQuery(t *testing.T) {
	resp := buildMockResponse(P0F_STATUS_BADQUERY, "", "", "")

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, &resp)

	var parsed P0fResponse
	err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &parsed)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if parsed.Status != P0F_STATUS_BADQUERY {
		t.Errorf("Status should be BADQUERY (0x00), got 0x%02x", parsed.Status)
	}
}

func TestResponseStringExtraction(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"simple", "Linux", "Linux"},
		{"with_spaces", "Windows 10", "Windows 10"},
		{"max_length", "1234567890123456789012345678901", "1234567890123456789012345678901"}, // 31 chars
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var field [P0F_STR_MAX + 1]byte
			copy(field[:], tc.input)

			result := bytesToString(field[:])
			if result != tc.expected {
				t.Errorf("bytesToString(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestDistanceSignedValue(t *testing.T) {
	// Distance -1 means unavailable
	resp := P0fResponse{
		Magic:    0x50304602,
		Status:   P0F_STATUS_OK,
		Distance: -1,
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, &resp)

	var parsed P0fResponse
	binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &parsed)

	if parsed.Distance != -1 {
		t.Errorf("Distance should preserve -1 (unavailable), got %d", parsed.Distance)
	}
}

func TestStatusConstants(t *testing.T) {
	if P0F_STATUS_BADQUERY != 0x00 {
		t.Errorf("P0F_STATUS_BADQUERY should be 0x00, got 0x%02x", P0F_STATUS_BADQUERY)
	}
	if P0F_STATUS_OK != 0x10 {
		t.Errorf("P0F_STATUS_OK should be 0x10, got 0x%02x", P0F_STATUS_OK)
	}
	if P0F_STATUS_NOMATCH != 0x20 {
		t.Errorf("P0F_STATUS_NOMATCH should be 0x20, got 0x%02x", P0F_STATUS_NOMATCH)
	}
}

func TestAddressTypeConstants(t *testing.T) {
	if P0F_ADDR_IPV4 != 0x04 {
		t.Errorf("P0F_ADDR_IPV4 should be 0x04, got 0x%02x", P0F_ADDR_IPV4)
	}
	if P0F_ADDR_IPV6 != 0x06 {
		t.Errorf("P0F_ADDR_IPV6 should be 0x06, got 0x%02x", P0F_ADDR_IPV6)
	}
}

func TestMatchQualityFlags(t *testing.T) {
	if P0F_MATCH_FUZZY != 0x01 {
		t.Errorf("P0F_MATCH_FUZZY should be 0x01, got 0x%02x", P0F_MATCH_FUZZY)
	}
	if P0F_MATCH_GENERIC != 0x02 {
		t.Errorf("P0F_MATCH_GENERIC should be 0x02, got 0x%02x", P0F_MATCH_GENERIC)
	}

	// Test combined flags (fuzzy + generic = 0x03)
	both := P0F_MATCH_FUZZY | P0F_MATCH_GENERIC
	if both != 0x03 {
		t.Errorf("FUZZY | GENERIC should be 0x03, got 0x%02x", both)
	}
}

func TestResponseMagicBytes(t *testing.T) {
	expected := [4]byte{0x50, 0x30, 0x46, 0x02}
	if P0F_RESP_MAGIC != expected {
		t.Errorf("Response magic should be %v, got %v", expected, P0F_RESP_MAGIC)
	}
}

func TestQueryMagicConstant(t *testing.T) {
	expected := [4]byte{0x50, 0x30, 0x46, 0x01}
	if P0F_QUERY_MAGIC != expected {
		t.Errorf("Query magic should be %v, got %v", expected, P0F_QUERY_MAGIC)
	}
}

func TestStringMaxLength(t *testing.T) {
	if P0F_STR_MAX != 31 {
		t.Errorf("P0F_STR_MAX should be 31, got %d", P0F_STR_MAX)
	}
}

// Helper functions

func buildMockResponse(status uint32, osName, osFlavor, linkType string) P0fResponse {
	resp := P0fResponse{
		Magic:      0x50304602, // P0F_RESP_MAGIC as uint32 little-endian
		Status:     status,
		FirstSeen:  1609459200, // 2021-01-01 00:00:00 UTC
		LastSeen:   1609459260,
		TotalCount: 42,
		UptimeMin:  1440,
		UpModDays:  7,
		Distance:   5,
		OsMatchQ:   0,
	}
	copy(resp.OsName[:], osName)
	copy(resp.OsFlavor[:], osFlavor)
	copy(resp.LinkType[:], linkType)
	return resp
}

func bytesToString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

// Mock p0f server for integration tests

type mockP0fServer struct {
	listener net.Listener
	sockPath string
	response P0fResponse
}

func newMockServer(t *testing.T, resp P0fResponse) *mockP0fServer {
	t.Helper()
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "p0f.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}

	server := &mockP0fServer{
		listener: listener,
		sockPath: sockPath,
		response: resp,
	}

	go server.serve()
	return server
}

func (s *mockP0fServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *mockP0fServer) handleConn(conn net.Conn) {
	defer conn.Close()

	for {
		// Read 21-byte query
		query := make([]byte, 21)
		_, err := conn.Read(query)
		if err != nil {
			return
		}

		// Send response
		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, &s.response)
		conn.Write(buf.Bytes())
	}
}

func (s *mockP0fServer) close() {
	s.listener.Close()
	os.Remove(s.sockPath)
}

func TestNewWithValidSocket(t *testing.T) {
	resp := buildMockResponse(P0F_STATUS_OK, "Linux", "3.x", "Ethernet")
	server := newMockServer(t, resp)
	defer server.close()

	client, err := New(server.sockPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	if client.conn == nil {
		t.Error("Expected connection to be established")
	}
	if client.socket != server.sockPath {
		t.Errorf("Socket path mismatch: got %s, want %s", client.socket, server.sockPath)
	}
}

func TestClose(t *testing.T) {
	resp := buildMockResponse(P0F_STATUS_OK, "Linux", "3.x", "Ethernet")
	server := newMockServer(t, resp)
	defer server.close()

	client, err := New(server.sockPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Close should not panic
	client.Close()

	// Subsequent operations should fail
	_, err = client.Query(net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("Expected error after Close()")
	}
}

func TestQuerySuccess(t *testing.T) {
	expectedResp := buildMockResponse(P0F_STATUS_OK, "Linux", "3.x", "Ethernet")
	server := newMockServer(t, expectedResp)
	defer server.close()

	client, err := New(server.sockPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	resp, err := client.Query(net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}

	if resp.Status != P0F_STATUS_OK {
		t.Errorf("Status: got 0x%02x, want 0x%02x", resp.Status, P0F_STATUS_OK)
	}

	osName := bytesToString(resp.OsName[:])
	if osName != "Linux" {
		t.Errorf("OsName: got %q, want %q", osName, "Linux")
	}

	osFlavor := bytesToString(resp.OsFlavor[:])
	if osFlavor != "3.x" {
		t.Errorf("OsFlavor: got %q, want %q", osFlavor, "3.x")
	}

	if resp.TotalCount != 42 {
		t.Errorf("TotalCount: got %d, want %d", resp.TotalCount, 42)
	}

	if resp.Distance != 5 {
		t.Errorf("Distance: got %d, want %d", resp.Distance, 5)
	}
}

func TestQueryIPv6(t *testing.T) {
	expectedResp := buildMockResponse(P0F_STATUS_OK, "Windows", "10", "Ethernet")
	server := newMockServer(t, expectedResp)
	defer server.close()

	client, err := New(server.sockPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	resp, err := client.Query(net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}

	if resp.Status != P0F_STATUS_OK {
		t.Errorf("Status: got 0x%02x, want 0x%02x", resp.Status, P0F_STATUS_OK)
	}
}

func TestQueryNoMatch(t *testing.T) {
	expectedResp := buildMockResponse(P0F_STATUS_NOMATCH, "", "", "")
	server := newMockServer(t, expectedResp)
	defer server.close()

	client, err := New(server.sockPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	resp, err := client.Query(net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}

	if resp.Status != P0F_STATUS_NOMATCH {
		t.Errorf("Status: got 0x%02x, want 0x%02x", resp.Status, P0F_STATUS_NOMATCH)
	}
}

func TestQueryBadQuery(t *testing.T) {
	expectedResp := buildMockResponse(P0F_STATUS_BADQUERY, "", "", "")
	server := newMockServer(t, expectedResp)
	defer server.close()

	client, err := New(server.sockPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	resp, err := client.Query(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}

	if resp.Status != P0F_STATUS_BADQUERY {
		t.Errorf("Status: got 0x%02x, want 0x%02x", resp.Status, P0F_STATUS_BADQUERY)
	}
}

func TestQueryNegativeDistance(t *testing.T) {
	expectedResp := buildMockResponse(P0F_STATUS_OK, "Linux", "5.x", "WiFi")
	expectedResp.Distance = -1 // Distance unavailable
	server := newMockServer(t, expectedResp)
	defer server.close()

	client, err := New(server.sockPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	resp, err := client.Query(net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}

	if resp.Distance != -1 {
		t.Errorf("Distance: got %d, want -1 (unavailable)", resp.Distance)
	}
}

func TestMultipleQueries(t *testing.T) {
	expectedResp := buildMockResponse(P0F_STATUS_OK, "FreeBSD", "12", "Ethernet")
	server := newMockServer(t, expectedResp)
	defer server.close()

	client, err := New(server.sockPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}
	for _, ipStr := range ips {
		resp, err := client.Query(net.ParseIP(ipStr))
		if err != nil {
			t.Errorf("Query(%s) failed: %v", ipStr, err)
			continue
		}
		if resp.Status != P0F_STATUS_OK {
			t.Errorf("Query(%s) status: got 0x%02x, want 0x%02x", ipStr, resp.Status, P0F_STATUS_OK)
		}
	}
}

// Mock server that closes connection after receiving query (simulates read error)
type mockClosingServer struct {
	listener net.Listener
	sockPath string
}

func newMockClosingServer(t *testing.T) *mockClosingServer {
	t.Helper()
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "p0f.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}

	server := &mockClosingServer{
		listener: listener,
		sockPath: sockPath,
	}

	go server.serve()
	return server
}

func (s *mockClosingServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		// Read query then close without sending response
		query := make([]byte, 21)
		conn.Read(query)
		conn.Close()
	}
}

func (s *mockClosingServer) close() {
	s.listener.Close()
	os.Remove(s.sockPath)
}

func TestQueryReadError(t *testing.T) {
	server := newMockClosingServer(t)
	defer server.close()

	client, err := New(server.sockPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	_, err = client.Query(net.ParseIP("192.168.1.1"))
	if err == nil {
		t.Error("Expected error when server closes connection without response")
	}
}

// Benchmarks

func BenchmarkNewP0fQueryIPv4(b *testing.B) {
	ip := net.ParseIP("192.168.1.100")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		newP0fQuery(ip)
	}
}

func BenchmarkNewP0fQueryIPv6(b *testing.B) {
	ip := net.ParseIP("2001:db8::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		newP0fQuery(ip)
	}
}

func BenchmarkQuerySerialization(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := newP0fQuery(ip)
		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, q)
	}
}

func BenchmarkResponseDeserialization(b *testing.B) {
	resp := buildMockResponse(P0F_STATUS_OK, "Linux", "5.x", "Ethernet")
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, &resp)
	data := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var parsed P0fResponse
		binary.Read(bytes.NewReader(data), binary.LittleEndian, &parsed)
	}
}

func BenchmarkBytesToString(b *testing.B) {
	var field [P0F_STR_MAX + 1]byte
	copy(field[:], "Linux")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytesToString(field[:])
	}
}

func BenchmarkQueryRoundtrip(b *testing.B) {
	resp := buildMockResponse(P0F_STATUS_OK, "Linux", "5.x", "Ethernet")
	tmpDir := b.TempDir()
	sockPath := filepath.Join(tmpDir, "p0f.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}
	defer listener.Close()

	// Start server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				query := make([]byte, 21)
				for {
					_, err := c.Read(query)
					if err != nil {
						return
					}
					var buf bytes.Buffer
					binary.Write(&buf, binary.LittleEndian, &resp)
					c.Write(buf.Bytes())
				}
			}(conn)
		}
	}()

	client, err := New(sockPath)
	if err != nil {
		b.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	ip := net.ParseIP("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.Query(ip)
	}
}
