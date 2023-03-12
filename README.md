# IP Checker

- Check IP addresses against a large set of IP address ranges.
- Pass in a file or URL, e.g. an access log or a DB export containing one or more IP addresses per line.
- Checks IPs against known [datacenter IP ranges](https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv) by default, using data from [this project](https://github.com/jhassine/server-ip-addresses).
- Uses an Interval Tree for fast matching. Able to check `>500k IPs` against `>33k IP ranges` in a couple of seconds (on a MacBook Pro).

## Docker Image

Image available on Docker hub: https://hub.docker.com/repository/docker/anrid/ipcheck/general

## Usage

A file with some [test IPs](/data/test-ips.txt) is included in the Docker image at `/test-ips.txt`.

```bash
# Each line in the input file may contain text besides IP addresses, e.g.:
$ cat data/test-ips.txt

20.150.136.0
15.177.101.100
aws----ip3.64.226.240
aaazureee51.105.74.151eeeruzaaa
2023-03-11.10:10:10.2302039293      access_log--ip:4.4.4.4aaa,8.8.8.8

# The program uses a regexp to find all IPs on each line in the input file (will match one or more IPs per line).

# To check IPs against known datacenter IP ranges, simply do:
$ docker run --rm anrid/ipcheck -i /test-ips.txt

20.150.136.0          | 20.150.128.0         - 20.150.255.255       Azure
3.64.226.240          | 3.64.0.0             - 3.79.255.255         AWS
51.105.74.151         | 51.105.64.0          - 51.105.79.255        Azure
found 3 matches | checked 6 IPs against 33365 ranges (0 dupes)
```

- It scanned the input file and found `6` IPs.
- It tested `6` IPs against `33,365` IP ranges and found `3` matches.

```bash
# To check ~600,000 IPs that I've exported from access logs stored in Bigquery:
$ time docker run --rm -v $(pwd)/../bigquery-exports:/data anrid/ipcheck -i /data/bq-results-20230311.csv

... 879 rows omitted ...

43.207.143.206        | 43.206.0.0           - 43.207.255.255       AWS
52.194.239.9          | 52.194.0.0           - 52.195.255.255       AWS
34.173.1.69           | 34.172.0.0           - 34.173.255.255       GCP
found 882 matches | checked 588933 IPs against 33365 ranges (0 dupes)

real    0m2.111s
user    0m0.074s
sys     0m0.027s
```

- Checked `588,933` unique IPs against `33,365` IP ranges and found `882` matches.
- Runtime was `2.1 sec` on a MacBook Pro.

```bash
# To check against other IP ranges create a CSV file in this format:
$ cat data/test-ranges.txt

"cidr","hostmin","hostmax","vendor"
"x","3.0.0.0","3.1.255.255","AWS"
"x","3.0.5.32","3.0.5.39","AWS"
"x","3.64.226.240","3.64.226.243","AWS"

# Then pass in your CSV file using the --ip-ranges flag:
$ docker run --rm -v $(pwd)/data:/data anrid/ipcheck -i /data/test-ips.txt --ip-ranges /data/test-ranges.txt

3.64.226.240          | 3.64.226.240         - 3.64.226.243         AWS
found 1 matches | checked 6 IPs against 3 ranges (0 dupes)
```

- Note that the CIDR column is ignored by the program.
