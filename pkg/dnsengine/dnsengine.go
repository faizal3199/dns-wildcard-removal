package dnsengine

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"github.com/miekg/dns"
)

/*
resultPair is used to for passing data in channel
*/
type resultPair struct {
	res common.DNSRecordSet
	err error
}

/*
dnsClientWithQueryMessage hold pointers to dns.Client and dns.Msg
*/
type dnsClientWithQueryMessage struct {
	client     *dns.Client
	msg        *dns.Msg
	domainName string
}

/*
createDNSRecordSetFromAnswer creates a common.DNSRecordSet from dns.Msg.Answer(alias to []RR) structure
*/
func createDNSRecordSetFromAnswer(answer []dns.RR) (common.DNSRecordSet, error) {
	dnsRecordsObject := common.DNSRecordSet{}

	for _, record := range answer {
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

/*
resolveWithSingleResolver attempts to query the message m to provides resolver.
*/
func (x *dnsClientWithQueryMessage) resolveWithSingleResolver(resolver common.IPAddressType,
	valueChan chan<- resultPair, ctx context.Context) {
	r, _, _ := x.client.Exchange(
		x.msg,
		net.JoinHostPort(resolver, "53"),
	)

	var result resultPair

	if r == nil {
		result = resultPair{
			res: nil,
			err: fmt.Errorf("failed to resolve: %s", x.domainName),
		}
	} else {
		recordSet, err := createDNSRecordSetFromAnswer(r.Answer)

		if err == nil {
			result = resultPair{
				res: recordSet,
				err: nil,
			}
		} else {
			result = resultPair{
				res: nil,
				err: err,
			}
		}
	}

	select {
	case <-ctx.Done():
		return
	case valueChan <- result:
		return
	}
}

/*
GetDNSRecords returns CNAME or A records for given domain name
*/
func GetDNSRecords(resolvers common.DNSServers, domain common.DomainType) (common.DNSRecordSet, error) {
	x := new(dnsClientWithQueryMessage)
	x.domainName = common.SanitizeDomainName(domain)
	x.client = new(dns.Client)

	tmpMsg := new(dns.Msg)
	tmpMsg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	tmpMsg.RecursionDesired = true
	x.msg = tmpMsg

	// Can't use a channel because that will only provide value to one goroutine
	// and leave other hanging causing leak
	ctx, cancel := context.WithCancel(context.Background())
	valueChan := make(chan resultPair)

	defer func() {
		// Cancel the context, this will signal all remaining go routines to return
		// No need to close the channel it will be garbage collected
		cancel()
	}()

	waitCount := 0

	for _, resolver := range resolvers {
		go x.resolveWithSingleResolver(resolver, valueChan, ctx)
		waitCount++
	}

	// Wait until one resolver gives satisfactory reply
	// In case no one provides satisfactory reply exit the loop
	for waitCount > 0 {
		result := <-valueChan

		if result.err == nil {
			return result.res, result.err
		}

		waitCount--
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
