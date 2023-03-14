package firehol

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anrid/ipcheck/pkg/iputil"
)

const (
	fireHOLBlocklistRepoURL = "https://github.com/firehol/blocklist-ipsets/archive/refs/heads/master.zip"
)

func Import(outDir string, forceDownload bool) {
	createDirIfNotExists(outDir)

	unpackedDir := filepath.Join(outDir, "blocklist-ipsets-master")
	zipFile := filepath.Join(outDir, "master.zip")

	if isDir(unpackedDir) {
		fmt.Printf("Found previously downloaded Git repo: %s\n", unpackedDir)

		if forceDownload {
			fmt.Printf("Force download flag passed, removing local files and downloading Git repo again ..\n")

			err := os.RemoveAll(unpackedDir)
			if err != nil {
				log.Fatalf("could not delete existing dir: %s - error: %s", unpackedDir, err)
			}
			// Try deleting old zip archive.
			os.Remove(zipFile)

			wgetURL(fireHOLBlocklistRepoURL, outDir)
			unzip(outDir, zipFile)
		}
	} else {
		wgetURL(fireHOLBlocklistRepoURL, outDir)
		unzip(outDir, zipFile)
	}

	files := findAllIPAndNetsets(unpackedDir)
	fmt.Printf("Found %d IP sets\n", len(files))

	outFile := filepath.Join(outDir, "firehol.ips")
	of, err := os.Create(outFile)
	if err != nil {
		log.Fatalf("could not create output file: %s - %s", outFile, err)
	}
	defer of.Close()

	excluded := []string{
		"ipdeny_country",
		"ipip_country",
		"ip2location_country",
		"geolite2_country",
	}

	var importedSets, importedRanges, importedIPs int64
	dupes := make(map[uint32]bool)
	var numDupes int64

SKIP:
	for _, f := range files {
		for _, ex := range excluded {
			if strings.Contains(f, ex) {
				continue SKIP
			}
		}

		ips := loadIPSet(f)
		importedSets++

		fmt.Printf("Loaded IP set: %s (%d CIDRs, %d IPs)\n", ips.Name, len(ips.CIDRs), len(ips.IPs))

		if len(ips.CIDRs) > 0 || len(ips.IPs) > 0 {
			of.WriteString(fmt.Sprintf("# %s | %s | %s (%d CIDRs, %d IPs)\n", ips.Name, ips.Maintainer, ips.MaintainerURL, len(ips.CIDRs), len(ips.IPs)))

			for _, cidr := range ips.CIDRs {
				of.WriteString(cidr)
				of.WriteString("\n")
				importedRanges++
			}
			for _, ip := range ips.IPs {
				ipn := iputil.IP2Long(ip)

				// Skip dupes!
				if !dupes[ipn] {
					of.WriteString(ip)
					of.WriteString("\n")
					importedIPs++

					dupes[ipn] = true
				} else {
					numDupes++
				}
			}
		}
	}

	fmt.Printf(
		"\nImported FireHOL %d blocklists (%d ranges, %d blocked / flagged IPs, %d dupes)\n",
		importedSets, importedRanges, importedIPs, numDupes,
	)
}

type IPSet struct {
	Name          string
	Maintainer    string
	MaintainerURL string
	CIDRs         []string
	IPs           []string
}

func loadIPSet(file string) *IPSet {
	// fmt.Printf("Loading IP Set: %s\n", file)

	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("could not load IPSet from file: %s - error: %s", file, err)
	}

	ips := new(IPSet)
	lines := strings.Split(string(b), "\n")
	var cc int

	for _, l := range lines {
		if len(l) == 1 && l[0] == '#' {
			// Single comment.
			cc++
			continue
		}

		if len(l) > 1 {
			if l[0:2] == "# " {
				if cc == 1 {
					// Name of IP set.
					ips.Name = l[2:]
				} else if cc == 4 {
					if strings.HasPrefix(l, "# Maintainer URL") {
						parts := strings.Split(l, " : ")
						ips.MaintainerURL = parts[1]
					} else if strings.HasPrefix(l, "# Maintainer") {
						parts := strings.Split(l, " : ")
						ips.Maintainer = parts[1]
					}
				}
			} else if len(l) >= 8 {
				// Found IP or CIDR.
				if strings.Contains(l, "/") {
					// Is CIDR.
					ips.CIDRs = append(ips.CIDRs, l)
				} else {
					ips.IPs = append(ips.IPs, l)
				}
			}
		}
	}

	return ips
}

func findAllIPAndNetsets(dir string) (files []string) {
	var totalSize int64

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			if strings.HasSuffix(info.Name(), ".netset") || strings.HasSuffix(info.Name(), ".ipset") {
				// fmt.Printf("Found: %s\n", path)
				files = append(files, path)
				totalSize += info.Size()
			}
		}

		return nil
	})
	if err != nil {
		log.Println(err)
	}

	return
}

func wgetURL(url, dir string) {
	res := mustExecCommand("wget", "-q", "-P", dir, url)
	fmt.Println(res)
}

func unzip(outDir, file string) {
	res := mustExecCommand("unzip", "-oq", "-d", outDir, file)
	fmt.Println(res)
}

func mustExecCommand(command string, args ...string) (stdoutStderr string) {
	fmt.Printf("Running command:\n%s %v\n", command, args)

	cmd := exec.Command(command, args...)
	o, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	stdoutStderr = string(o)
	return
}

func isDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		log.Panicf("unknown error: %s", err)
	}
	return s.IsDir()
}

func createDirIfNotExists(path string) {
	s, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Panicf("could not access path %s - error: %s", path, err)
		}

		fmt.Printf("Creating dir %s ..", path)
		err = os.Mkdir(path, 0777)
		if err != nil {
			log.Fatalf("could not create dir %s", path)
		}
	} else {
		if !s.IsDir() {
			log.Fatalf("path %s is not a dir", path)
		}
	}
}
