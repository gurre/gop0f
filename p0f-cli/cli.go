// gop0f cli is a utility for accessing the p0f api from the command-line
package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/goccy/go-json"
	"github.com/gurre/gop0f"
)

var (
	flagUnixsock = flag.String("s", "/var/run/p0f.socket", "Location of the p0f unix socket.")
	flagOutput   = flag.String("o", "grep", "Output in grep|json format.")
	flagQuery    = flag.String("q", "", "IP to query for.")
	flagVersion  = flag.Bool("v", false, "Display version and exit.")
	VERSION      string // Set by GOXC
)

type OutputResponse struct {
	Status     string `json:"status"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	TotalCount uint32 `json:"total_count"`
	UptimeMin  uint32 `json:"uptime_min"`
	UpModDays  uint32 `json:"upmod_days"`
	LastNat    string `json:"last_nat,omitempty"`
	LastChg    string `json:"last_chg,omitempty"`
	Distance   int32  `json:"distance"`
	BadSw      bool   `json:"bad_sw"`
	OsMatchQ   string `json:"os_match_quality"`
	OsName     string `json:"os_name"`
	OsFlavor   string `json:"os_flavor"`
	HttpName   string `json:"http_name,omitempty"`
	HttpFlavor string `json:"http_flavor,omitempty"`
	LinkType   string `json:"link_type"`
	Language   string `json:"language,omitempty"`
}

func main() {
	flag.Parse()
	if *flagVersion {
		fmt.Printf("p0f-cli %s\n", VERSION)
		os.Exit(0)
	}

	if *flagQuery == "" {
		fmt.Fprintln(os.Stderr, "error: -q flag is required")
		flag.Usage()
		os.Exit(1)
	}

	p0fclient, err := gop0f.New(*flagUnixsock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer p0fclient.Close()

	ip := net.ParseIP(*flagQuery)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "error: invalid IP address: %s\n", *flagQuery)
		os.Exit(1)
	}

	resp, err := p0fclient.Query(ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	out := convertResponse(resp)

	switch *flagOutput {
	case "json":
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	case "grep":
		printGrep(out)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown output format: %s (use grep or json)\n", *flagOutput)
		os.Exit(1)
	}
}

func convertResponse(resp gop0f.P0fResponse) OutputResponse {
	return OutputResponse{
		Status:     statusString(resp.Status),
		FirstSeen:  formatTime(resp.FirstSeen),
		LastSeen:   formatTime(resp.LastSeen),
		TotalCount: resp.TotalCount,
		UptimeMin:  resp.UptimeMin,
		UpModDays:  resp.UpModDays,
		LastNat:    formatTimeOptional(resp.LastNat),
		LastChg:    formatTimeOptional(resp.LastChg),
		Distance:   int32(resp.Distance),
		BadSw:      resp.BadSw != 0,
		OsMatchQ:   matchQualityString(resp.OsMatchQ),
		OsName:     bytesToString(resp.OsName[:]),
		OsFlavor:   bytesToString(resp.OsFlavor[:]),
		HttpName:   bytesToString(resp.HttpName[:]),
		HttpFlavor: bytesToString(resp.HttpFlavor[:]),
		LinkType:   bytesToString(resp.LinkType[:]),
		Language:   bytesToString(resp.Language[:]),
	}
}

func bytesToString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

func statusString(status uint32) string {
	switch status {
	case gop0f.P0F_STATUS_OK:
		return "ok"
	case gop0f.P0F_STATUS_BADQUERY:
		return "bad_query"
	case gop0f.P0F_STATUS_NOMATCH:
		return "no_match"
	default:
		return fmt.Sprintf("unknown(%d)", status)
	}
}

func matchQualityString(q byte) string {
	switch {
	case q&gop0f.P0F_MATCH_FUZZY != 0:
		return "fuzzy"
	case q&gop0f.P0F_MATCH_GENERIC != 0:
		return "generic"
	default:
		return "normal"
	}
}

func formatTime(t uint32) string {
	if t == 0 {
		return ""
	}
	return time.Unix(int64(t), 0).Format(time.RFC3339)
}

func formatTimeOptional(t uint32) string {
	if t == 0 {
		return ""
	}
	return time.Unix(int64(t), 0).Format(time.RFC3339)
}

func printGrep(out OutputResponse) {
	fmt.Printf("status=%s\n", out.Status)
	if out.FirstSeen != "" {
		fmt.Printf("first_seen=%s\n", out.FirstSeen)
	}
	if out.LastSeen != "" {
		fmt.Printf("last_seen=%s\n", out.LastSeen)
	}
	fmt.Printf("total_count=%d\n", out.TotalCount)
	fmt.Printf("uptime_min=%d\n", out.UptimeMin)
	fmt.Printf("upmod_days=%d\n", out.UpModDays)
	if out.LastNat != "" {
		fmt.Printf("last_nat=%s\n", out.LastNat)
	}
	if out.LastChg != "" {
		fmt.Printf("last_chg=%s\n", out.LastChg)
	}
	fmt.Printf("distance=%d\n", out.Distance)
	fmt.Printf("bad_sw=%t\n", out.BadSw)
	fmt.Printf("os_match_quality=%s\n", out.OsMatchQ)
	if out.OsName != "" {
		fmt.Printf("os_name=%s\n", out.OsName)
	}
	if out.OsFlavor != "" {
		fmt.Printf("os_flavor=%s\n", out.OsFlavor)
	}
	if out.HttpName != "" {
		fmt.Printf("http_name=%s\n", out.HttpName)
	}
	if out.HttpFlavor != "" {
		fmt.Printf("http_flavor=%s\n", out.HttpFlavor)
	}
	if out.LinkType != "" {
		fmt.Printf("link_type=%s\n", out.LinkType)
	}
	if out.Language != "" {
		fmt.Printf("language=%s\n", out.Language)
	}
}
