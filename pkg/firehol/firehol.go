package firehol

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anrid/ipcheck/pkg/iputil"
	"github.com/pkg/errors"
)

const (
	fireHOLBlocklistRepoURL = "https://github.com/firehol/blocklist-ipsets/archive/refs/heads/master.zip"
)

func Download(outDir string, forceDownload bool) error {
	err := createDirIfNotExists(outDir)
	if err != nil {
		errors.Wrapf(err, "failed to create FireHOL import dir: %s", outDir)
	}

	unpackedDir := filepath.Join(outDir, "blocklist-ipsets-master")
	zipFile := filepath.Join(outDir, "master.zip")

	if isDir(unpackedDir) {
		fmt.Printf("Found previously downloaded Git repo: %s\n", unpackedDir)

		if forceDownload {
			fmt.Printf("Force download flag passed, removing local files and downloading Git repo again ..\n")

			// Delete existing FireHOL blocklist repo dir.
			err := os.RemoveAll(unpackedDir)
			if err != nil {
				return errors.Wrapf(err, "could not delete existing dir: %s", unpackedDir)
			}
			// Try deleting old zip archive.
			os.Remove(zipFile)

			err = wgetURL(fireHOLBlocklistRepoURL, outDir)
			if err != nil {
				return errors.Wrapf(err, "could not execute `wget` command on URL: %s", fireHOLBlocklistRepoURL)
			}
			unzip(outDir, zipFile)
			if err != nil {
				return errors.Wrapf(err, "could not execute `unzip` command on zip file: %s", zipFile)
			}
		}
	} else {
		err = wgetURL(fireHOLBlocklistRepoURL, outDir)
		if err != nil {
			return errors.Wrapf(err, "could not execute `wget` command on URL: %s", fireHOLBlocklistRepoURL)
		}
		err = unzip(outDir, zipFile)
		if err != nil {
			return errors.Wrapf(err, "could not execute `unzip` command on zip file: %s", zipFile)
		}
	}

	files, err := findAllIPAndNetsets(unpackedDir)
	if err != nil {
		return errors.Wrap(err, "FireHOL import failed")
	}

	fmt.Printf("Found %d IP sets\n", len(files))

	outFile := filepath.Join(outDir, "firehol.ips")
	of, err := os.Create(outFile)
	if err != nil {
		return errors.Wrapf(err, "could not create output file: %s", outFile)
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

		ips, err := loadIPSet(f)
		if err != nil {
			fmt.Printf("Skipping invaild IP set: %s\n", f)
			continue
		}

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

	return nil
}

type IPSet struct {
	Name          string
	Maintainer    string
	MaintainerURL string
	CIDRs         []string
	IPs           []string
}

func loadIPSet(file string) (*IPSet, error) {
	// fmt.Printf("Loading IP Set: %s\n", file)
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "could not load IPSet from file: %s", file)
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

	return ips, nil
}

func findAllIPAndNetsets(dir string) (files []string, err error) {
	var totalSize int64

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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
		return nil, errors.Wrapf(err, "could not walk dir: %s", dir)
	}

	return files, nil
}

func wgetURL(url, dir string) error {
	res, err := execCommand("wget", "-q", "-P", dir, url)
	fmt.Println(res)
	return err
}

func unzip(outDir, file string) error {
	res, err := execCommand("unzip", "-oq", "-d", outDir, file)
	fmt.Println(res)
	return err
}

func execCommand(command string, args ...string) (stdoutStderr string, err error) {
	fmt.Printf("Running command:\n%s %v\n", command, args)

	cmd := exec.Command(command, args...)
	o, err := cmd.CombinedOutput()
	if err != nil {
		return "", errors.Wrapf(err, "could not execute command: %s %v", command, args)
	}

	return string(o), nil
}

func isDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		log.Panicf("unknown error when checking dir: %s  -  error: %s", path, err)
	}
	return s.IsDir()
}

func createDirIfNotExists(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.Wrapf(err, "could not access path %s", path)
		}

		fmt.Printf("Creating dir %s ..", path)
		err = os.Mkdir(path, 0777)
		if err != nil {
			return errors.Wrapf(err, "could not create dir %s", path)
		}
	} else {
		if !s.IsDir() {
			return errors.Errorf("path %s is not a dir", path)
		}
	}
	return nil
}
