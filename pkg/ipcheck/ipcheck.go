package ipcheck

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/anrid/ipcheck/pkg/interval"
	"github.com/anrid/ipcheck/pkg/iputil"
	"github.com/pkg/errors"
)

const (
	debug = false
)

type CheckAgainstIPRangesParams struct {
	InputFileORURL              string
	IPRangesCSVFileOrURL        string
	FireHOLFile                 string
	ShowAdditionalBlocklistInfo bool
	VerboseOutput               bool
	ToCSVFile                   string
}

func CheckAgainstIPRanges(p CheckAgainstIPRangesParams) (numMatchedIPsFound int, err error) {
	ipRanges := interval.NewIntervalTree()
	ipNumbers := make(map[uint32]uint16)
	ipNumberSources := make(map[uint16]string)
	var numRanges int

	if p.VerboseOutput {
		fmt.Printf("Reading IP ranges from %s ..\n", p.IPRangesCSVFileOrURL)
	}
	readCSVFileOrURL(p.IPRangesCSVFileOrURL, func(recordNumber int, record []string) error {
		if recordNumber == 1 {
			// Skip headers.
			return nil
		}

		cidr := record[0]
		vendor := record[3]
		start, end, err := iputil.CIDRToIPRange(cidr)
		if err != nil {
			return err
		}

		r, err := interval.NewInterval(start, end)
		if err != nil {
			return err
		}

		ipRanges.Upsert(r, vendor)

		numRanges++

		return nil
	})

	if p.VerboseOutput {
		fmt.Printf("Loaded %d IP ranges into interval tree\n", numRanges)
		fmt.Printf("Loaded %d IPs into hash map\n", len(ipNumbers))
	}

	// Check against FireHOL data imported from here: https://github.com/firehol/blocklist-ipsets
	// If you don't know, FireHOL is "an iptables stateful packet filtering firewall for humans!".
	// Learn more at https://github.com/firehol/firehol.
	if p.FireHOLFile != "" {
		if p.VerboseOutput {
			fmt.Printf("Loading FireHOL data from %s (this takes a while) ..\n", p.FireHOLFile)
		}

		f, err := os.Open(p.FireHOLFile)
		if err != nil {
			return 0, errors.Wrapf(err, "could not open FireHOL DB file: %s", p.FireHOLFile)
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
					if !p.ShowAdditionalBlocklistInfo {
						parts := strings.Split(src, " | ")
						src = parts[0]
					}
					srcID++
					ipNumberSources[srcID] = src
					continue
				}

				if strings.ContainsRune(t, '/') {
					// CIDR
					start, end, err := iputil.CIDRToIPRange(t)
					if err != nil {
						return 0, err
					}

					r, err := interval.NewInterval(start, end)
					if err != nil {
						return 0, errors.Wrapf(err, "could not create interval for CIDR %s (%s - %s)", t, start, end)
					}

					ipRanges.Upsert(r, src)

					numRanges++
				} else {
					// IP
					ipNumbers[iputil.IP2Long(t)] = srcID
				}
			}
		}
		if p.VerboseOutput {
			fmt.Printf("Loaded %d IP ranges into interval tree\n", numRanges)
			fmt.Printf("Loaded %d IPs into hash map\n", len(ipNumbers))
		}
	}

	findIPs := regexp.MustCompile(`(^|[^\d\.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^\d\.]|$)`)
	var numIPsFound, numDupes int
	dupes := make(map[string][]string)
	matchedIPs := [][]string{{"IP", "Info"}}

	readFileOrURL(p.InputFileORURL, func(lineNumber int, line string) error {
		ipsFound := findIPs.FindAllStringSubmatch(line, -1)

		for _, match := range ipsFound {
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
				info := fmt.Sprintf("%s | %s - %s", res.Payload, res.Interval.IPRangeMin, res.Interval.IPRangeMax)
				if _, found := dupes[ip]; found {
					numDupes++
				} else {
					matchedIPs = append(matchedIPs, []string{ip, info})
				}
				dupes[ip] = append(dupes[ip], info)

				if p.ToCSVFile == "" {
					fmt.Printf("%s  <==  %-5s | %s - %s\n", line, res.Payload, res.Interval.IPRangeMin, res.Interval.IPRangeMax)
				}
				numMatchedIPsFound++
				continue
			}

			ipn := iputil.IP2Long(ip)

			if srcID, found := ipNumbers[ipn]; found {
				// Found matching IP.
				src := ipNumberSources[srcID]

				if _, found := dupes[ip]; found {
					numDupes++
				} else {
					matchedIPs = append(matchedIPs, []string{ip, src})
				}
				dupes[ip] = append(dupes[ip], src)

				if p.ToCSVFile == "" {
					fmt.Printf("%s  <==  %s\n", line, src)
				}
				numMatchedIPsFound++
			}
		}

		return nil
	})

	fmt.Printf(
		"\nFound %d matches | Checked %d IPs against %d ranges and %d blocked or flagged IPs (%d dupes)\n",
		numMatchedIPsFound, numIPsFound, numRanges, len(ipNumbers), numDupes,
	)

	if p.ToCSVFile != "" {
		err = matchedIPsToCSVFile(p.ToCSVFile, matchedIPs)
		if err != nil {
			return 0, err
		}
		fmt.Printf("Wrote %s\n", p.ToCSVFile)
	}

	return numMatchedIPsFound, nil
}

type IPMap struct {
	Vendor string
	IPs    map[uint32]bool
}

func matchedIPsToCSVFile(file string, matchedIPs [][]string) error {
	f, err := os.Create(file)
	if err != nil {
		return errors.Wrapf(err, "could not create CSV file: %s", file)
	}
	defer f.Close()

	err = csv.NewWriter(f).WriteAll(matchedIPs)
	if err != nil {
		return errors.Wrapf(err, "could not write %d matched IPs to CSV file: %s", len(matchedIPs), file)
	}

	return nil
}

func readCSVFileOrURL(fileOrURL string, forEachRecord func(recordNumber int, record []string) error) error {
	file := fileOrURL

	_, err := os.Stat(fileOrURL)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.Wrapf(err, "got unexpected error when trying to stat file (or URL): %s", fileOrURL)
		}

		// Treat this as a URL. Download its contents to a local temp location.
		file, err = downloadURLToTempFile(fileOrURL)
		if err != nil {
			return err
		}
	}

	// Treat file as a local CSV file at this point.

	f, err := os.Open(file)
	if err != nil {
		return errors.Wrapf(err, "failed to open CSV file: %s", file)
	}
	defer f.Close()

	cr := csv.NewReader(f)
	var recordNumber int

	for {
		rec, err := cr.Read()
		if err != nil {
			if err != io.EOF {
				return errors.Wrapf(err, "failed to read CSV record from file: %s", file)
			}
			// We're done.
			break
		}

		recordNumber++
		err = forEachRecord(recordNumber, rec)
		if err != nil {
			return errors.Wrapf(err, "failed to process CSV record")
		}
	}

	return nil
}

func readFileOrURL(fileOrURL string, forEachLine func(lineNumber int, line string) error) error {
	file := fileOrURL

	_, err := os.Stat(fileOrURL)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.Wrapf(err, "got unexpected error when trying to stat file (or URL): %s", fileOrURL)
		}

		// Treat this as a URL. Download its contents to a local temp location.
		file, err = downloadURLToTempFile(fileOrURL)
		if err != nil {
			return err
		}
	}

	// Treat file as a local file at this point.

	f, err := os.Open(file)
	if err != nil {
		return errors.Wrapf(err, "failed to open file: %s", file)
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
			return errors.Wrapf(err, "failed to process line")
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.Wrapf(err, "failed to read line from file: %s", file)
	}

	return nil
}

func downloadURLToTempFile(url string) (filename string, err error) {
	res, err := http.Get(url)
	if err != nil {
		return "", errors.Wrapf(err, "failed to download data from URL: %s", url)
	}

	if res.StatusCode >= 400 {
		return "", errors.Errorf("failed to download data from URL: %s - got status code: %d", url, res.StatusCode)
	}

	// Create a temp file.
	f, err := os.CreateTemp(os.TempDir(), "ips-to-check-csv")
	if err != nil {
		return "", errors.Wrapf(err, "failed to create a temp file to store data in")
	}
	defer f.Close()

	_, err = io.Copy(f, res.Body)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read data from HTTP response from URL: %s", url)
	}

	return f.Name(), nil
}
