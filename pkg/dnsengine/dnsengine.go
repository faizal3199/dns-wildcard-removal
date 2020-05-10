package dnsengine

import (
	"fmt"
	"net"
	"strings"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"github.com/miekg/dns"
)

/*
GetDNSRecords returns CNAME or A records for given domain name
*/
func GetDNSRecords(resolvers common.DNSServers, domain common.DomainType) (common.DNSRecordSet, error) {
	c := new(dns.Client)
	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	dnsRecordsObject := common.DNSRecordSet{}

	for _, resolver := range resolvers {
		r, _, _ := c.Exchange(
			m,
			net.JoinHostPort(resolver, "53"),
		)

		if r != nil {
			for _, record := range r.Answer {
				queryName := record.Header().Name
				recordType := dns.Type(record.Header().Rrtype).String()
				recordValue := ""

				switch v := record.(type) {
				case *dns.A:
					recordValue = v.A.String()
				case *dns.CNAME:
					recordValue = v.Target
				case *dns.NS:
					recordValue = v.Ns
				}

				if recordValue == "" {
					return nil, fmt.Errorf("unknown record type: %v", record)
				}

				newRecord := common.DNSRecord{Name: queryName, Type: recordType, Value: recordValue}
				dnsRecordsObject = append(dnsRecordsObject, newRecord)
			}

			return dnsRecordsObject, nil
		}
	}

	return nil, fmt.Errorf("Failed to resolve: %s", domain)
}

/*
GetParentDomain returns parent domain upto TLD. After which it returns error
*/
func GetParentDomain(domain string, jobDomain string) (string, error) {
	domain = strings.ToLower(domain)
	domain = strings.TrimSpace(domain)
	domain = strings.Trim(domain, ".")

	jobDomain = strings.ToLower(jobDomain)
	jobDomain = strings.TrimSpace(jobDomain)
	jobDomain = strings.Trim(jobDomain, ".")

	parts := strings.Split(domain, ".")
	jobParts := strings.Split(jobDomain, ".")

	domain += "."
	jobDomain += "."

	if len(parts) > len(jobParts) {
		parentDomain := strings.Join(parts[1:], ".")
		parentDomain += "."
		return parentDomain, nil
	}
	// Return root & error
	return jobDomain, fmt.Errorf("parent domain out-of-scope for '%s', in context of '%s'", domain, jobDomain)
}
