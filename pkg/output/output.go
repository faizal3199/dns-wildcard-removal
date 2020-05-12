package output

import (
	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"os"
)

func getOutputFile(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdout, nil
	} else {
		return os.Create(path)
	}
}

/*
writeADomainOutputToFile write output for a single domain to output file
*/
func writeADomainOutputToFile(file *os.File, data string) error {
	_, err := file.Write([]byte(data))
	if err != nil {
		return err
	}

	_, err = file.Write([]byte("\n"))

	return err
}

/*
StartWritingOutput write the DNS records from the channel to output file. This is a blocking method,
it waits until there are no more records to write
*/
func StartWritingOutput(outputFilePath string, c <-chan common.DomainRecords) error {
	outputFile, err := getOutputFile(outputFilePath)

	if err != nil {
		return err
	}

	defer outputFile.Close()

	for {
		domainRecord, more := <-c

		if !more {
			break
		}

		if domainRecord.Records[0].Type == "A" {
			err := writeADomainOutputToFile(outputFile, domainRecord.Records.String())
			if err != nil {
				return err
			}
		} else {
			err := writeADomainOutputToFile(outputFile, domainRecord.Records[0].String())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

/*
CreateChannel return a new channel for passing DomainRecords
*/
func CreateChannel() chan common.DomainRecords {
	return make(chan common.DomainRecords)
}
