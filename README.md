# gop0f

Go client library for [p0f](https://lcamtuf.coredump.cx/p0f3/), the passive OS fingerprinting tool by Michal Zalewski.

p0f identifies operating systems and software on both endpoints of a TCP connection by analyzing network traffic passively—without sending any probes that could trigger alarms or be blocked by firewalls.

## Features

- Query p0f daemon via Unix socket API
- IPv4 and IPv6 support
- Command-line tool included
- Output in grep or JSON format

## Requirements

p0f v3 must be running with the `-s` flag to enable the API socket:

```
p0f -i eth0 -s /var/run/p0f.socket
```

## Installation

```
go get github.com/gurre/gop0f
```

## Library Usage

```go
package main

import (
    "fmt"
    "log"
    "net"

    "github.com/gurre/gop0f"
)

func main() {
    client, err := gop0f.New("/var/run/p0f.socket")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    resp, err := client.Query(net.ParseIP("192.168.1.100"))
    if err != nil {
        log.Fatal(err)
    }

    if resp.Status == gop0f.P0F_STATUS_OK {
        fmt.Printf("OS: %s %s\n", resp.OsName, resp.OsFlavor)
        fmt.Printf("Link: %s\n", resp.LinkType)
        fmt.Printf("Distance: %d hops\n", resp.Distance)
    }
}
```

## CLI Usage

```
p0f-cli -q <ip> [-s socket] [-o format]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-q` | (required) | IP address to query |
| `-s` | /var/run/p0f.socket | Path to p0f Unix socket |
| `-o` | grep | Output format: `grep` or `json` |
| `-v` | | Show version |

### Examples

Query with default socket:
```
p0f-cli -q 192.168.1.100
```

Query with custom socket and JSON output:
```
p0f-cli -s /tmp/p0f.sock -q 10.0.0.1 -o json
```

### Output Formats

**grep** (default):
```
status=ok
first_seen=2024-01-15T10:30:00Z
last_seen=2024-01-15T10:35:00Z
total_count=42
uptime_min=1440
distance=5
os_name=Linux
os_flavor=3.x
link_type=Ethernet
```

**json**:
```json
{
  "status": "ok",
  "first_seen": "2024-01-15T10:30:00Z",
  "last_seen": "2024-01-15T10:35:00Z",
  "total_count": 42,
  "uptime_min": 1440,
  "distance": 5,
  "os_name": "Linux",
  "os_flavor": "3.x",
  "link_type": "Ethernet"
}
```

## Response Fields

| Field | Type | Description |
|-------|------|-------------|
| Status | uint32 | Query result: OK (0x10), NO_MATCH (0x20), BAD_QUERY (0x00) |
| FirstSeen | uint32 | Unix timestamp when host was first observed |
| LastSeen | uint32 | Unix timestamp of most recent traffic |
| TotalCount | uint32 | Total number of connections observed |
| UptimeMin | uint32 | Estimated system uptime in minutes (0 if unknown) |
| UpModDays | uint32 | Uptime modulo in days |
| LastNat | uint32 | Last NAT/load balancer detection time (0 if never) |
| LastChg | uint32 | Last OS mismatch detection time |
| Distance | int16 | Network distance in hops (-1 if unavailable) |
| BadSw | byte | User-Agent accuracy: 0=unknown, 1=OS mismatch, 2=mismatch |
| OsMatchQ | byte | Match quality: 0=normal, 1=fuzzy, 2=generic, 3=both |
| OsName | string | Detected operating system name |
| OsFlavor | string | OS version/flavor |
| HttpName | string | Detected HTTP application |
| HttpFlavor | string | HTTP application version |
| LinkType | string | Network link type (Ethernet, DSL, etc.) |
| Language | string | System language if detected |

## Constants

```go
// Status codes
P0F_STATUS_BADQUERY = 0x00  // Invalid query
P0F_STATUS_OK       = 0x10  // Match found
P0F_STATUS_NOMATCH  = 0x20  // No match in cache

// Address types
P0F_ADDR_IPV4 = 0x04
P0F_ADDR_IPV6 = 0x06

// Match quality flags
P0F_MATCH_FUZZY   = 0x01  // Fuzzy match
P0F_MATCH_GENERIC = 0x02  // Generic signature
```

## p0f Capabilities

p0f can detect:

- **Operating systems** from TCP SYN and SYN+ACK signatures
- **HTTP clients/servers** from request/response headers
- **Network topology** including NAT, load balancers, and proxies
- **System uptime** from TCP timestamp analysis
- **Network distance** via TTL analysis
- **Forged headers** when User-Agent doesn't match OS fingerprint
- **System language** from HTTP Accept-Language

## Performance

| Operation | Time | Memory | Allocations |
|-----------|------|--------|-------------|
| Query creation (IPv4) | ~14 ns | 24 B | 1 |
| Query creation (IPv6) | ~11 ns | 24 B | 1 |
| Query serialization | ~116 ns | 160 B | 4 |
| Response deserialization | ~800 ns | 288 B | 2 |
| Full roundtrip (with I/O) | ~4.1 µs | 2.1 KB | 10 |

Run benchmarks: `go test -bench=. -benchmem`

## Test Coverage

- Library: 100% coverage
- CLI helpers: 100% coverage (excluding main)

Run tests: `go test -v -cover ./...`

## Breaking Changes

### v2.0 (current)

**`P0fResponse.Distance` type changed from `uint32` to `int16`**

This change was required to match the p0f protocol specification, which defines distance as a signed 16-bit value where -1 indicates "unavailable".

Migration:
```go
// Before (incorrect type)
var dist uint32 = resp.Distance

// After (correct type)
var dist int16 = resp.Distance
if dist == -1 {
    // distance unavailable
}
```

## References

- [p0f v3 homepage](https://lcamtuf.coredump.cx/p0f3/)
- [p0f README](https://lcamtuf.coredump.cx/p0f3/README)
