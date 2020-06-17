package dnshandler

import (
	"bufio"
	"fmt"
	"os"

	"github.com/faizal3199/dns-wildcard-removal/pkg/dnsengine"
	log "github.com/sirupsen/logrus"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
)

/*
generateCannotOpenFileError generates an error using predefined template "cannot open file: %s"
*/
func generateCannotOpenFileError(path string) error {
	return fmt.Errorf("cannot open file: %s", path)
}

/*
checkIfFileIsOkay performs following checks
1) File exists
2) Not a directory
*/
func checkIfFileIsOkay(filePath string) bool {
	fInfo, err := os.Stat(filePath)

	if os.IsNotExist(err) {
		return false
	}

	if fInfo.IsDir() {
		return false
	}

	return true
}

/*
getInputFile check the file for given path and
if valid returns pointer to os.File object for that file
*/
func getInputFile(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	}

	if checkIfFileIsOkay(path) {
		return os.Open(path)
	}
	return nil, generateCannotOpenFileError(path)

}

/*
ResolveFromInputFile resolves domains provided by "inputFile". Input file should contain
one domain per line. The resolved domains are sent to buffered channel "c"
*/
func ResolveFromInputFile(inputFile string, resolvers common.DNSServers, c chan<- common.DomainRecords) error {
	if !checkIfFileIsOkay(inputFile) {
		return generateCannotOpenFileError(inputFile)
	}

	fileObj, err := getInputFile(inputFile)
	if err != nil {
		return generateCannotOpenFileError(inputFile)
	}

	go func() {
		scanner := bufio.NewScanner(fileObj)
		defer fileObj.Close()

		for scanner.Scan() {
			domainName := scanner.Text()

			if domainName == "" {
				continue
			}

			recordSet, err := dnsengine.GetDNSRecords(resolvers, domainName)

			if err != nil {
				log.Infof("Got error while resolving %s\nerr = %v", domainName, err)
				continue
			}

			// NX domain
			if len(recordSet) == 0 {
				continue
			}

			domainRecord := common.DomainRecords{
				DomainName: common.SanitizeDomainName(domainName),
				Records:    recordSet,
			}

			c <- domainRecord
		}

		close(c)
	}()

	return nil
}

/*
CreateChannel return a new buffered channel for passing DomainRecords.
The size of buffer is 100
*/
func CreateChannel() chan common.DomainRecords {
	return make(chan common.DomainRecords, 100)
}
