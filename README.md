# IP Checker

- Check IPs against a large set of IP ranges.
- Pass in a file or URL.
- Checks against known [datacenter IP ranges](https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv) by default.
- Uses an Interval Tree for fast matching.

## Usage

Docker image available at `anrid/ipcheck`.

A file with some [test IPs](/data/test-ips.txt) is included in the Docker image at `/test-ips.txt`.

```bash
# Check against some test IPs included in the Docker image:
$ docker run --rm -it anrid/ipcheck -i /test-ips.txt
20.150.136.0          | 20.150.128.0         - 20.150.255.255       Azure
3.64.226.240          | 3.64.0.0             - 3.79.255.255         AWS
51.105.74.151         | 51.105.64.0          - 51.105.79.255        Azure
found 3 matches | checked 6 IPs against 33365 ranges (0 dupes)
```

- Scanned test file and found `6` IPs.
- Found `3` matches within `33,365` IP ranges`.

```bash
# Check against a 600,000 IPs exported from Bigquery:
$ time docker run --rm -it -v $(pwd)/../bigquery-exports:/data  anrid/ipcheck -i /data/bq-results-20230311.csv

... 879 rows omitted ...

43.207.143.206        | 43.206.0.0           - 43.207.255.255       AWS
52.194.239.9          | 52.194.0.0           - 52.195.255.255       AWS
34.173.1.69           | 34.172.0.0           - 34.173.255.255       GCP
found 882 matches | checked 588933 IPs against 33365 ranges (0 dupes)

real    0m2.111s
user    0m0.074s
sys     0m0.027s
```

- Found `882` matches when testing `588,933` unique IPs against `33,365` IP ranges. Took `2.1 sec` on my MacBook Pro.
