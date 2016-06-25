// gop0f cli is a utility for accessing the p0f api from the command-line
package main

import (
	"flag"
	"fmt"
	"github.com/gurre/gop0f"
	"net"
	"os"
)

var (
	flagUnixsock = flag.String("s", "/var/run/p0f.socket", "Location of the p0f unix socket.")
	flagOutput   = flag.String("o", "grep", "Output in grep|json format.")
	flagQuery    = flag.String("q", "", "IP to query for.")
	flagVersion  = flag.Bool("v", false, "Display version and exit.")
	VERSION      string // Set by GOXC
)

func main() {
	flag.Parse()
	if *flagVersion {
		fmt.Printf("p0f-cli %s\n", VERSION)
		os.Exit(0)
	}

	p0fclient, err := gop0f.New(*flagUnixsock)
	if err != nil {
		panic(err)
	}

	ip := net.ParseIP(*flagQuery)
	if ip == nil {
		panic("Not valid ip")
	}

	resp, err := p0fclient.Query(ip)
	if err != nil {
		panic(err)
	}
	fmt.Println(resp)

}
