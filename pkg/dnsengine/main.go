package dnsengine

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"github.com/miekg/dns"
)

/*
GetDNSRecords returns CNAME or A records for given domain name
*/
func GetDNSRecords(resolvers common.DNSServers, domain common.DomainType) (common.DomainRecords, error) {
	c := new(dns.Client)
	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	dnsRecordsObject := common.DomainRecords{}
	dnsRecordsObject.Records = []common.DNSRecord{}

	for _, resolver := range resolvers {
		r, _, _ := c.Exchange(
			m,
			net.JoinHostPort(resolver, "53"),
		)

		if r != nil {
			for _, record := range r.Answer {
				recordType := dns.Type(record.Header().Rrtype).String()
				recordValue := ""

				switch v := record.(type) {
				case *dns.A:
					recordValue = v.A.String()
				case *dns.CNAME:
					recordValue = strings.TrimRight(v.Target, ".")
				case *dns.NS:
					recordValue = v.Ns
				}

				if recordValue == "" {
					log.Fatal("Unkown record type")
					log.Fatal(record)
				}

				newRecord := common.DNSRecord{Type: recordType, Value: recordValue}
				dnsRecordsObject.Records = append(dnsRecordsObject.Records, newRecord)
			}

			return dnsRecordsObject, nil
		}
	}

	return dnsRecordsObject, fmt.Errorf("Failed to resolve: %s", domain)
}
