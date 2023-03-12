package main

import (
	"os"

	"github.com/anrid/ipcheck/pkg/ipcheck"
	"github.com/spf13/pflag"
)

func main() {
	ipRangesFileOrURL := pflag.String("ip-ranges", "https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv", "Path or URL to a CSV file with IP ranges to test against.")
	inputFileOrURL := pflag.StringP("input-file", "i", "", "Path or URL to an input file containing IP addresses to check. This can be an uncompressed text file in any format. The program finds all IPs addresses on each line and tests them against all ranges.")
	verbose := pflag.Bool("verbose", false, "Verbose output, helps when troubleshooting.")

	pflag.Parse()

	if *inputFileOrURL == "" || *ipRangesFileOrURL == "" {
		pflag.Usage()
		os.Exit(-1)
	}

	ipcheck.CheckAgainstIPRanges(*inputFileOrURL, *ipRangesFileOrURL, *verbose)
}
