package parser

import (
	"bufio"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"

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

		parsedDomainsCount := 0

		for scanner.Scan() {
			line := scanner.Text()

			// Reset objects
			if line == "" {
				if currentDomainRecords != nil {
					c <- *currentDomainRecords
					currentDomainRecords = nil
					parsedDomainsCount++

					if parsedDomainsCount%10000 == 0 {
						log.Infof("Number of domains parsed until now: %d", parsedDomainsCount)
					}
				}
				continue
			}

			parts := strings.Split(line, " ")

			// Create new DNS Record and set the corresponding Domain
			if currentDomainRecords == nil {
				currentDomainRecords = new(common.DomainRecords)
				currentDomainRecords.DomainName = common.SanitizeDomainName(parts[0])
			}

			var newRecord common.DNSRecord

			if parts[1] == "CNAME" {
				newRecord = common.DNSRecord{
					Name: common.SanitizeDomainName(parts[0]),
					Type: parts[1],
					// sanitize the value if it's a CNAME
					Value: common.SanitizeDomainName(parts[2]),
				}
			} else {
				newRecord = common.DNSRecord{
					Name:  common.SanitizeDomainName(parts[0]),
					Type:  parts[1],
					Value: parts[2],
				}
			}

			currentDomainRecords.Records = append(currentDomainRecords.Records, newRecord)
		}

		if currentDomainRecords != nil {
			c <- *currentDomainRecords
			currentDomainRecords = nil
			parsedDomainsCount++
		}

		log.Infof("Number of domains parsed from massdns output: %d", parsedDomainsCount)
		log.Infoln("Closing parser output channel")
	}()
}

/*
CreateChannel return a new channel for passing DomainRecords
*/
func CreateChannel() chan common.DomainRecords {
	return make(chan common.DomainRecords)
}
