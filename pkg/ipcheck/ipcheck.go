package ipcheck

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/anrid/ipcheck/pkg/interval"
	"github.com/anrid/ipcheck/pkg/iputil"
)

const (
	debug = false
)

func CheckAgainstIPRanges(inputFileOrURL, ipRangesCSVFileOrURL, fireHOLFile string, verboseOutput bool) (numMatchesFound int) {
	ipRanges := interval.NewIntervalTree()
	ipNumbers := make(map[uint32]uint16)
	ipNumberSources := make(map[uint16]string)
	var numRanges int

	if verboseOutput {
		fmt.Printf("Reading IP ranges from %s ..\n", ipRangesCSVFileOrURL)
	}
	readCSVFileOrURL(ipRangesCSVFileOrURL, func(recordNumber int, record []string) error {
		if recordNumber == 1 {
			// Skip headers.
			return nil
		}

		cidr := record[0]
		vendor := record[3]
		start, end := iputil.CIDRToIPRange(cidr)

		r, err := interval.NewInterval(start, end)
		if err != nil {
			return err
		}

		ipRanges.Upsert(r, vendor)

		numRanges++

		return nil
	})

	if verboseOutput {
		fmt.Printf("Loaded %d IP ranges into interval tree\n", numRanges)
		fmt.Printf("Loaded %d IPs into hash map\n", len(ipNumbers))
	}

	// Check against FireHOL data imported from here: https://github.com/firehol/blocklist-ipsets
	// If you don't know, FireHOL is "an iptables stateful packet filtering firewall for humans!".
	// Learn more at https://github.com/firehol/firehol.
	if fireHOLFile != "" {
		if verboseOutput {
			fmt.Printf("Loading FireHOL data from %s (this takes a while) ..\n", fireHOLFile)
		}

		f, err := os.Open(fireHOLFile)
		if err != nil {
			log.Fatalf("could not open FireHOL DB file: %s - error: %s\n", fireHOLFile, err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		var src string
		var srcID uint16

		for scanner.Scan() {
			t := scanner.Text()
			if len(t) > 0 {
				if t[0] == '#' {
					src = t[2:]
					srcID++
					ipNumberSources[srcID] = src
					continue
				}

				if strings.ContainsRune(t, '/') {
					// CIDR
					start, end := iputil.CIDRToIPRange(t)

					r, err := interval.NewInterval(start, end)
					if err != nil {
						log.Panicf("could not create interval for CIDR %s (%s - %s)", t, start, end)
					}

					ipRanges.Upsert(r, src)

					numRanges++
				} else {
					// IP
					ipNumbers[iputil.IP2Long(t)] = srcID
				}
			}
		}
		if verboseOutput {
			fmt.Printf("Loaded %d IP ranges into interval tree\n", numRanges)
			fmt.Printf("Loaded %d IPs into hash map\n", len(ipNumbers))
		}
	}

	matchIP := regexp.MustCompile(`(^|[^\d\.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^\d\.]|$)`)
	var numIPsFound, numDupes int
	dupes := make(map[string][]string)

	readFileOrURL(inputFileOrURL, func(lineNumber int, line string) error {
		matches := matchIP.FindAllStringSubmatch(line, -1)

		for _, match := range matches {
			if len(match) < 3 {
				continue
			}

			ip := match[2]
			numIPsFound++

			if debug {
				fmt.Printf("checking ip: %v\n", ip)
			}

			r, err := interval.NewInterval(ip, ip)
			if err != nil {
				return err
			}

			res, err := ipRanges.FindFirstOverlapping(r)
			if err == nil {
				// Found overlapping range.
				info := fmt.Sprintf("%-20s - %-20s | %s", res.Interval.IPRangeMin, res.Interval.IPRangeMax, res.Payload)
				if _, found := dupes[ip]; found {
					numDupes++
				}
				dupes[ip] = append(dupes[ip], info)

				fmt.Printf("%-20s | %-20s - %-20s | %s\n", ip, res.Interval.IPRangeMin, res.Interval.IPRangeMax, res.Payload)
				numMatchesFound++
				continue
			}

			ipn := iputil.IP2Long(ip)

			if srcID, found := ipNumbers[ipn]; found {
				// Found matching IP.
				src := ipNumberSources[srcID]

				if _, found := dupes[ip]; found {
					numDupes++
				}
				dupes[ip] = append(dupes[ip], src)

				fmt.Printf("%-20s | %s\n", ip, src)
				numMatchesFound++
			}
		}

		return nil
	})

	fmt.Printf(
		"\nFound %d matches | Checked %d IPs against %d ranges and %d blocked or flagged IPs (%d dupes)\n",
		numMatchesFound, numIPsFound, numRanges, len(ipNumbers), numDupes,
	)

	return
}

type IPMap struct {
	Vendor string
	IPs    map[uint32]bool
}

func readCSVFileOrURL(fileOrURL string, forEachRecord func(recordNumber int, record []string) error) {
	file := fileOrURL

	_, err := os.Stat(fileOrURL)
	if err != nil {
		if err == os.ErrNotExist {
			log.Fatalf("got unexpected error when trying to stat file (or URL): %s - error: %s", fileOrURL, err)
		}

		// Treat this as a URL. Download its contents to a local temp location.
		file = downloadURLToTempFile(fileOrURL)
	}

	// Treat file as a local CSV file at this point.

	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("failed to open CSV file: %s - error: %s", file, err)
	}
	defer f.Close()

	cr := csv.NewReader(f)
	var recordNumber int

	for {
		rec, err := cr.Read()
		if err != nil {
			if err != io.EOF {
				log.Fatalf("failed to read CSV record from file: %s - error: %s", file, err)
			}
			// We're done.
			break
		}

		recordNumber++
		err = forEachRecord(recordNumber, rec)
		if err != nil {
			log.Fatalf("failed to process CSV record - error: %s", err)
		}
	}
}

func readFileOrURL(fileOrURL string, forEachLine func(lineNumber int, line string) error) {
	file := fileOrURL

	_, err := os.Stat(fileOrURL)
	if err != nil {
		if err == os.ErrNotExist {
			log.Fatalf("got unexpected error when trying to stat file (or URL): %s - error: %s", fileOrURL, err)
		}

		// Treat this as a URL. Download its contents to a local temp location.
		file = downloadURLToTempFile(fileOrURL)
	}

	// Treat file as a local file at this point.

	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("failed to open file: %s - error: %s", file, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lineNumber int

	// Optionally, resize scanner's capacity for lines over 64K!
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		err := forEachLine(lineNumber, line)
		if err != nil {
			log.Fatalf("failed to process line - error: %s", err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("failed to read line from file: %s - error: %s", file, err)
	}
}

func downloadURLToTempFile(url string) (filename string) {
	res, err := http.Get(url)
	if err != nil {
		log.Fatalf("failed to download data from URL: %s - error: %s", url, err)
	}

	if res.StatusCode >= 400 {
		log.Fatalf("failed to download data from URL: %s - got status code: %d", url, res.StatusCode)
	}

	// Create a temp file.
	f, err := os.CreateTemp(os.TempDir(), "ips-to-check-csv")
	if err != nil {
		log.Fatalf("failed to create a temp file to store data in - error: %s", err)
	}
	defer f.Close()

	_, err = io.Copy(f, res.Body)
	if err != nil {
		log.Fatalf("failed to read data from HTTP response from URL: %s - error: %s", url, err)
	}

	return f.Name()
}
