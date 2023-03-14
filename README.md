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
aws---- ip3.2.35.193
aaazureee 20.209.46.151xxx
2023-03-11.10:10:10.23020 access_log--ip:4.4.4.4 aaa 8.8.8.8
```

- Each line in the input file may contain text besides IP addresses.
- The program uses a regexp to find all IPs on each line in the input file (can match one or more IPs per line).

## Basic Usage

To check IPs against known datacenter IP ranges, simply do:

```bash
$ docker run --rm anrid/ipcheck -i /test-ips.txt

34.64.161.255        | 34.64.160.0          - 34.64.191.255        | GCP
3.2.35.193           | 3.2.35.192           - 3.2.35.255           | AWS
20.209.46.151        | 20.209.0.0           - 20.209.255.255       | Azure

Found 3 matches | Checked 6 IPs against 33365 ranges and 0 blocked or flagged IPs (0 dupes)
```

- Scanned the input file and found `6` IPs.
- Checked `6` IPs against `33,365` IP ranges ([these](https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv) by default) and found `3` matches.

## Check a large number of IPs

To check `~600,000 IPs` stored in a file locally, e.g. exported from access logs stored in Bigquery:

```bash
$ docker run --rm -v $(pwd)/../bigquery-exports:/data anrid/ipcheck -i /data/bq-results-20230311.csv

.. lots of omitted ..

54.249.174.66        | 54.248.0.0           - 54.249.255.255       | AWS
13.231.129.239       | 13.230.0.0           - 13.231.255.255       | AWS
52.197.13.28         | 52.196.0.0           - 52.199.255.255       | AWS

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

34.64.161.255        | 34.64.160.0          - 34.64.191.255        | GCP
3.2.35.193           | 3.2.35.192           - 3.2.35.255           | AWS
20.209.46.151        | 20.209.46.0          - 20.209.47.255        | Azure

Found 3 matches | Checked 6 IPs against 3 ranges and 0 blocked or flagged IPs (0 dupes)
```

## Test against FireHOL blocklists

Begin by importing the FireHOL data to a local dir (in this example `../testing`):

```bash
$ docker run -v $(pwd)/../testing:/data anrid/ipcheck --import-firehol-to /data

Found 1337 IP sets
Loaded IP set: alienvault_reputation (0 CIDRs, 609 IPs)
Loaded IP set: asprox_c2 (0 CIDRs, 0 IPs)
Loaded IP set: bambenek_banjori (0 CIDRs, 136 IPs)
Loaded IP set: bambenek_bebloh (0 CIDRs, 0 IPs)
Loaded IP set: bambenek_c2 (0 CIDRs, 1 IPs)

.. lots of lines omitted ..

Loaded IP set: xroxy (0 CIDRs, 24 IPs)
Loaded IP set: xroxy_1d (0 CIDRs, 24 IPs)
Loaded IP set: xroxy_30d (0 CIDRs, 24 IPs)
Loaded IP set: xroxy_7d (0 CIDRs, 24 IPs)
Loaded IP set: yoyo_adservers (0 CIDRs, 9942 IPs)

Imported FireHOL 318 blocklists (120047 ranges, 3604185 blocked / flagged IPs, 4080332 dupes)
```

You should now have the following files locally:

```bash
$ ls -l ../testing

total 85436
drwxr-xr-x  3 root root     4096 Mar 12 10:28 ./
drwxr-xr-x 37 anri anri     4096 Mar 12 10:28 ../
drwxrwxrwx  6 root root    20480 Mar 12 10:28 blocklist-ipsets-master/
-rw-r--r--  1 root root 53482434 Mar 12 10:28 firehol.ips
-rw-r--r--  1 root root 33966427 Mar 12 10:28 master.zip
```

- `firehol.ips` now contains `120,047` IP ranges and `3,604,185` blocked / flagged IPs.

Check IPs against both the FireHOL database and the default datacenter ranges:

```bash
# Note that we're passing the `--verbose` to see more of what's going on.
$ docker run -v $(pwd)/../testing:/data anrid/ipcheck -i /test-ips.txt --firehol-file /data/firehol.ips --verbose

Reading IP ranges from https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv ..
Loaded 33365 IP ranges into interval tree
Loaded 0 IPs into hash map
Loading FireHOL data from /data/firehol.ips (this takes a while) ..
Loaded 153412 IP ranges into interval tree
Loaded 3604185 IPs into hash map

34.64.161.255        | 34.64.0.0            - 34.127.255.255       | pushing_inertia_blocklist | Pushing Inertia | https://github.com/pushinginertia/ip-blacklist (1307 CIDRs, 2 IPs)
3.2.35.193           | 3.2.35.192           - 3.2.35.255           | AWS
20.209.46.151        | 20.209.0.0           - 20.209.255.255       | Azure
4.4.4.4              | 4.0.0.0              - 4.255.255.255        | iblocklist_org_joost | iBlocklist.com | https://www.iblocklist.com/ (4 CIDRs, 0 IPs)

Found 4 matches | Checked 6 IPs against 153412 ranges and 3604185 blocked or flagged IPs (0 dupes)
```

- Note that loading the `firehol.ips` file into memory takes some time (`~15 sec` on a MacBook Pro).
