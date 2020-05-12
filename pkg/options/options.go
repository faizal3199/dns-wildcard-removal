package options

import (
	"bufio"
	"net"
	"os"
	"strings"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"

	"github.com/alexflint/go-arg"
)

type Options struct {
	Domain   string
	Input    string
	Resolver common.DNSServers
	Threads  int
	Output   string
}

type internalOptions struct {
	Domain   string `arg:"-d,required" help:"Domain to filter wildcard subdomains for"`
	Input    string `arg:"-i,required" help:"Path to input file of list of subdomains. Use - for stdin"`
	Resolver string `arg:"-r,required" help:"Path to file containing list of resolvers"`
	Threads  int    `arg:"-t" default:"4" help:"Number of threads to run"`
	Output   string `arg:"-o,required" help:"Path to output file. Use - for stdout"`
}

func parseListOfResolversFromList(filePath string) (common.DNSServers, error) {
	filePtr, err := os.Open(filePath)

	if err != nil {
		return nil, err
	}

	returnValue := make(common.DNSServers, 0)

	scanner := bufio.NewScanner(filePtr)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		ip := net.ParseIP(line)

		if ip != nil {
			returnValue = append(returnValue, ip.String())
		}
	}

	return returnValue, nil
}

/*
ParseOptionsArguments parses options from argument and return an instance of Options struct and error.
*/
func ParseOptionsArguments() (Options, error) {
	var parsedOptions internalOptions
	arg.MustParse(&parsedOptions)

	resolvers, err := parseListOfResolversFromList(parsedOptions.Resolver)
	if err != nil {
		return Options{}, err
	}

	returnOptions := Options{
		Domain:   parsedOptions.Domain,
		Input:    parsedOptions.Input,
		Resolver: resolvers,
		Threads:  parsedOptions.Threads,
		Output:   parsedOptions.Output,
	}

	return returnOptions, nil
}
