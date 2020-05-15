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
				queryName := common.SanitizeDomainName(record.Header().Name)
				recordType := dns.Type(record.Header().Rrtype).String()
				recordValue := ""

				switch v := record.(type) {
				case *dns.A:
					recordValue = v.A.String()
				case *dns.CNAME:
					recordValue = common.SanitizeDomainName(v.Target)
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

	return nil, fmt.Errorf("failed to resolve: %s", domain)
}

/*
GetParentDomain returns list of all parent domains for 'domain' upto 'jobDomain'. If 'domain' is
out of scope for 'jobDomain' it return error.
*/
func GetParentDomain(domain string, jobDomain string) ([]string, error) {
	domain = strings.Trim(common.SanitizeDomainName(domain), ".")
	jobDomain = strings.Trim(common.SanitizeDomainName(jobDomain), ".")

	parts := strings.Split(domain, ".")
	jobParts := strings.Split(jobDomain, ".")

	domain += "."
	jobDomain += "."

	if len(parts) < len(jobParts) {
		return nil, fmt.Errorf("domain out-of-scope for '%s', in context of '%s'", domain, jobDomain)
	} else if len(parts) == len(jobParts) {
		return []string{jobDomain}, nil
	} else {
		listTillTop := make([]string, 0)

		// Ignore the deepest label. We need it's parents
		parts := parts[1:]

		for i := len(parts) - len(jobParts); i >= 0; i-- {
			tmp := strings.Join(parts[i:], ".") + "."
			listTillTop = append(listTillTop, tmp)
		}

		return listTillTop, nil
	}
}
