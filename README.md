# dns-wildcard-removal
![Go Build](https://github.com/faizal3199/dns-wildcard-removal/workflows/Go%20Build/badge.svg)
![Go Test](https://github.com/faizal3199/dns-wildcard-removal/workflows/Go%20Test/badge.svg)

**dns-wildcard-removal** removes wildcard domains from the provided list of domains. Internally it uses *massdns* to speedly resolve all domain and then it itrerate over the results to quickly remove the wildcards.

# Install
## Dependencies
* [massdns](github.com/blechschmidt/massdns)

massdns's binary should be in PATH.

## Installation

```bash
go get -v github.com/faizal3199/dns-wildcard-removal
```

# Usage

```
$ dns-wildcard-removal -h
Usage: dns-wildcard-removal --domain DOMAIN --input INPUT --resolver RESOLVER [--threads THREADS] --output OUTPUT

Options:
  --domain DOMAIN, -d DOMAIN
                         Domain to filter wildcard subdomains for
  --input INPUT, -i INPUT
                         Path to input file of list of subdomains. Use - for stdin
  --resolver RESOLVER, -r RESOLVER
                         Path to file containing list of resolvers
  --threads THREADS, -t THREADS
                         Number of threads to run [default: 4]
  --output OUTPUT, -o OUTPUT
                         Path to output file. Use - for stdout
  --help, -h             display this help and exit
```