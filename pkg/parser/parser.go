package parser

import (
	"bufio"
	"io"
	"strings"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
)

/*
ParseAndPublishDNSRecords parsed the records from the io.PipeReader and published the records on
the channel `c`. Function closes the channel once there is no more input(pipe closed)
 */
func ParseAndPublishDNSRecords(reader *io.PipeReader, c chan<- common.DomainRecords) {
	scanner := bufio.NewScanner(reader)
	var currentDomainRecords *common.DomainRecords
	currentDomainRecords = nil

	// Start a new goroutine to parse data from massdns output
	// Pass the data into new channel
	go func() {
		// Close channel to indicate all records parsed
		defer close(c)

		// Close pipeReader to avoid any potential issues
		defer reader.Close()

		for scanner.Scan() {
			line := scanner.Text()

			// Reset objects
			if line == "" {
				if currentDomainRecords != nil {
					c <- *currentDomainRecords
					currentDomainRecords = nil
				}
				continue
			}

			parts := strings.Split(line, " ")

			// Create new DNS Record and set the corresponding Domain
			if currentDomainRecords == nil {
				currentDomainRecords = new(common.DomainRecords)
				currentDomainRecords.DomainName = parts[0]
			}

			currentDomainRecords.Records = append(currentDomainRecords.Records,
				common.DNSRecord{
					Name:  parts[0],
					Type:  parts[1],
					Value: parts[2],
				},
			)
		}

		if currentDomainRecords != nil {
			c <- *currentDomainRecords
			currentDomainRecords = nil
		}
	}()
}
