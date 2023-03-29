# IP Checker

- Check IP addresses against a large set of IP address ranges.
- Pass in a file or URL, e.g. an access log or a DB export containing one or more IP addresses per line.
- Checks IPs against known [datacenter IP ranges](https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv) by default, using data from [this project](https://github.com/jhassine/server-ip-addresses).
- Optionally checks IPs against all [FireHOL blocklists](https://github.com/firehol/blocklist-ipsets).
- Uses an Interval Tree for fast matching. Able to check `>500k IPs` against `>33k IP ranges` in a couple of seconds (on a MacBook Pro).

## Docker Image

Image available on Docker hub: https://hub.docker.com/repository/docker/anrid/ipcheck/general

## Input File

An input file with some [test IPs](data/test-ips.txt) can be found in inside the Docker image at `/test-ips.txt`:

```bash
$ docker run --rm --entrypoint bash anrid/ipcheck -c 'cat /test-ips.txt'

34.64.161.255
15.177.101.100
aws: ---- ip 3.2.35.193
azure(20.209.46.151)=xxx
2023-03-11.10:10:10.23020 access_log -- ip:4.4.4.4 | ip:8.8.8.8
```

- Each line in the input file may contain text besides IP addresses.
- The program uses a regexp to find all IPs on each line in the input file (can match one or more IPs per line).

## Basic Usage

To check an input file with IP addresses against known datacenter IP ranges:

```bash
$ docker run --rm anrid/ipcheck -i /test-ips.txt

34.64.161.255  <==  GCP   | 34.64.160.0 - 34.64.191.255
aws: ---- ip 3.2.35.193  <==  AWS   | 3.2.35.192 - 3.2.35.255
azure(20.209.46.151)=xxx  <==  Azure | 20.209.0.0 - 20.209.255.255

Found 3 matches | Checked 6 IPs against 33279 ranges and 0 blocked or flagged IPs (0 dupes)
```

- Scanned the input file and found `6` IPs.
- Checked `6` IPs against `33,365` IP ranges ([these](https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv) by default) and found `3` matches.

## Check a large number of IPs

To check `~600,000 IPs` stored in a file locally, e.g. exported from access logs stored in Bigquery:

```bash
$ docker run --rm -v $(pwd)/../bigquery-exports:/data anrid/ipcheck -i /data/bq-results-20230311.csv

.. lots of omitted ..

54.249.174.66   <==  AWS    | 54.248.0.0 - 54.249.255.255
13.231.129.239  <==  AWS    | 13.230.0.0 - 13.231.255.255
52.197.13.28    <==  AWS    | 52.196.0.0 - 52.199.255.255

Found 882 matches | Checked 588933 IPs against 33365 ranges and 0 blocked or flagged IPs (0 dupes)
```

- Checked `588,933` IPs against `33,365` IP ranges and found `882` matches.
- Runtime was `~2.2 sec` on a MacBook Pro.

## Supply your own IP ranges

To check against other IP ranges, create a CSV file in this format:

```bash
$ cat data/test-ranges.csv

"cidr","hostmin","hostmax","vendor"
"3.2.35.192/26","x","x","AWS"
"20.209.46.0/23","x","x","Azure"
"34.64.160.0/19","x","x","GCP"
```

- Only the `cidr` and `vendor` columns need to be filled in.

Then pass in your CSV file using the `--ip-ranges` flag:

```bash
$ docker run --rm -v $(pwd)/data:/data anrid/ipcheck -i /data/test-ips.txt --ip-ranges /data/test-ranges.csv
```

## Test against FireHOL blocklists

Being by downloading the lastest FireHOL blocklists to a local Docker volume:

```bash
# Create a new local Docker volume named `fire`
$ docker volume create fire
fire

# Download latest FireHOL blocklists into local Docker volume
$ docker run -v file:/data anrid/ipcheck --download /data/fire

Found 1337 IP sets
Loaded IP set: alienvault_reputation (0 CIDRs, 609 IPs)
Loaded IP set: asprox_c2 (0 CIDRs, 0 IPs)
Loaded IP set: bambenek_banjori (0 CIDRs, 136 IPs)

.. lots of lines omitted ..

Loaded IP set: xroxy_30d (0 CIDRs, 24 IPs)
Loaded IP set: xroxy_7d (0 CIDRs, 24 IPs)
Loaded IP set: yoyo_adservers (0 CIDRs, 9942 IPs)

Imported FireHOL 318 blocklists (120571 ranges, 3611584 blocked / flagged IPs, 4113069 dupes)
```

You should now have the following files in your Docker volume:

```bash
$ docker run -v file:/data --entrypoint bash anrid/ipcheck -c 'ls -l /data/fire'

total 85696
drwxrwxrwx    6 root     root         20480 Mar 10 01:05 blocklist-ipsets-master
-rw-r--r--    1 root     root      53595811 Mar 10 01:05 firehol.ips
-rw-r--r--    1 root     root      34136038 Mar 10 01:05 master.zip
```

- `firehol.ips` now contains `120,047` IP ranges and `3,604,185` blocked / flagged IPs.

To check an input file with IPs against both the FireHOL blocklists and the default datacenter ranges:

```bash
# Note that we're passing the `--verbose` to see more of what's going on.
$ docker run -v file:/data anrid/ipcheck -i /test-ips.txt --firehol-file /data/fire/firehol.ips --verbose

Reading IP ranges from https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv ..
Loaded 33279 IP ranges into interval tree
Loaded 0 IPs into hash map
Loading FireHOL data from /data/fire/firehol.ips (this takes a while) ..
Loaded 153850 IP ranges into interval tree
Loaded 3611584 IPs into hash map

34.64.161.255  <==  pushing_inertia_blocklist | Pushing Inertia | https://github.com/pushinginertia/ip-blacklist (1307 CIDRs, 2 IPs) | 34.64.0.0 - 34.127.255.255
aws---- ip3.2.35.193  <==  AWS   | 3.2.35.192 - 3.2.35.255
aaazureee 20.209.46.151xxx  <==  Azure | 20.209.0.0 - 20.209.255.255
2023-03-11.10:10:10.23020 access_log--ip:4.4.4.4 aaa 8.8.8.8  <==  iblocklist_org_joost | iBlocklist.com | https://www.iblocklist.com/ (4 CIDRs, 0 IPs) | 4.0.0.0 - 4.255.255.255

Found 4 matches | Checked 6 IPs against 153850 ranges and 3611584 blocked or flagged IPs (0 dupes)
```

- Note that loading the `firehol.ips` file into memory takes some time (`~15 sec` on a MacBook Pro).

### Output to CSV file

```bash
# Note that the `--to-csv-file` flag takes a path to an output file.
# In this case we output to a mounted local dir.
$ docker run -v file:/data -v $(pwd)/..:/out anrid/ipcheck -i /test-ips.txt --firehol-file /data/fire/firehol.ips --to-csv-file /out/blocked-ips.csv

Found 4 matches | Checked 6 IPs against 153850 ranges and 3611584 blocked or flagged IPs (0 dupes)
Wrote /out/blocked-ips.csv

# We now have a file named `blocked-ips.csv` in $(pwd)/..
$ cat ../blocked-ips.csv

IP,Info
34.64.161.255,"pushing_inertia_blocklist | Pushing Inertia | https://github.com/pushinginertia/ip-blacklist (1307 CIDRs, 2 IPs) | 34.64.0.0 - 34.127.255.255"
3.2.35.193,AWS | 3.2.35.192 - 3.2.35.255
20.209.46.151,Azure | 20.209.0.0 - 20.209.255.255
4.4.4.4,"iblocklist_org_joost | iBlocklist.com | https://www.iblocklist.com/ (4 CIDRs, 0 IPs) | 4.0.0.0 - 4.255.255.255"
```
