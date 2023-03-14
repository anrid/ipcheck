package main

import (
	"os"

	"github.com/anrid/ipcheck/pkg/firehol"
	"github.com/anrid/ipcheck/pkg/ipcheck"
	"github.com/spf13/pflag"
)

func main() {
	inputFileOrURL := pflag.StringP("input-file", "i", "", "Path or URL to an input file containing IP addresses to check. This can be an uncompressed text file in any format. The program finds all IPs addresses on each line and tests them against all ranges.")
	ipRangesFileOrURL := pflag.String("ip-ranges", "https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv", "Path or URL to a CSV file with IP ranges to test against.")
	importFireHOLTo := pflag.String("import-firehol-to", "", "Download all .ipset and .netset files from https://github.com/firehol/blocklist-ipsets and merge them into one big file named `firehol.ips` in this dir")
	fireHOLFile := pflag.StringP("firehol-file", "f", "", "Import all IP sets from https://github.com/firehol/blocklist-ipsets, merge them into one CSV file in this dir")
	verbose := pflag.Bool("verbose", false, "Verbose output, helps when troubleshooting.")

	pflag.Parse()

	if *importFireHOLTo != "" {
		firehol.Import(*importFireHOLTo, false /* force download latest data from the Firehol Github repo */)
		os.Exit(0)
	}

	if *inputFileOrURL == "" || *ipRangesFileOrURL == "" {
		pflag.Usage()
		os.Exit(-1)
	}

	ipcheck.CheckAgainstIPRanges(*inputFileOrURL, *ipRangesFileOrURL, *fireHOLFile, *verbose)
}
