package wildcardstruct

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"github.com/faizal3199/dns-wildcard-removal/pkg/dnsengine"
)

/*
WildcardDomain fetches and caches the result for random subdomains of a single parent domain
*/
type WildcardDomain struct {
	domainName  string
	mutex       sync.RWMutex
	result      []common.DNSRecordSet
	resolverErr error
	fetched     bool
}

const (
	// MaxDomainNameLength : Maximum length of a domain name(ignore last '.')
	MaxDomainNameLength = 253

	// MaxLabelLength : Maximum length of a label(doesn't include '.')
	MaxLabelLength = 63

	// ValidCharacters : Allowed characters in a label
	// Doesn't use '-' as it can't be the first character in a label
	ValidCharacters = "0123456789abcdefghijklmnopqrstuvwxyz"

	// Number of times result will be fetched
	numberOfTest = 10
)

func (d *WildcardDomain) lock() {
	d.mutex.Lock()
}

func (d *WildcardDomain) unlock() {
	d.mutex.Unlock()
}

func (d *WildcardDomain) readLock() {
	d.mutex.RLock()
}

func (d *WildcardDomain) readUnlock() {
	d.mutex.RUnlock()
}

/*
GetRandomSubdomain generates a "valid" subdomain with random label for given domain. A valid domain name is
1) total length <= 253
2) any label length <= 63
*/
func GetRandomSubdomain(domainName string) string {
	var maxLength int

	if (MaxDomainNameLength - len(domainName)) > MaxLabelLength {
		maxLength = MaxLabelLength
	} else {
		maxLength = MaxDomainNameLength - len(domainName)
	}

	newSubdomain := ""
	for i := 0; i < maxLength; i++ {
		newSubdomain += string(ValidCharacters[rand.Intn(len(ValidCharacters))])
	}

	return newSubdomain + "." + domainName
}

/*
fetchDNSRecordsInBackground acquires acquire write lock and then fetches DNS records in background.
Lock is released when record are fetched. Returns any error occurred before fetching records
*/
func (d *WildcardDomain) fetchDNSRecordsInBackground(resolvers common.DNSServers) {
	d.lock()

	if d.fetched {
		defer d.unlock()
		return
	}

	func() {
		defer d.unlock()

		i := numberOfTest - 1
		maxTests := numberOfTest * 2

		for i >= 0 && maxTests >= 0 {
			// Using random subdomains will also help avoid caching done by resolver
			randomSubdomain := GetRandomSubdomain(d.domainName)
			// Use all the resolvers to query the results instead of selecting a specific one.
			// As, a random subdomain is used this will lead to a virtually no chance of caching
			res, err := dnsengine.GetDNSRecords(resolvers, randomSubdomain)

			log.Debugf("Got DNS records for %s\nsubdomain = %s\nerr = %v\nres = %v",
				d.domainName, randomSubdomain, err, res)

			if err == nil {
				d.result = append(d.result, res)
				i-- // Keep resolving until we get all the successful instances
			} else {
				log.Infof("Got error while resolving a subdomain of %s\nsubdomain = %s\nerr = %v",
					d.domainName, randomSubdomain, err)
				d.resolverErr = fmt.Errorf("error resolving: %s", d.domainName)
			}

			// Avoid getting into infinite loop
			maxTests--
		}

		d.fetched = true
	}()
}

/*
GetResults checks if records are already fetched if so return else call fetchDNSRecordsInBackground
to fetch records and then recursively call GetResults. GetResults acquires read lock before checking
in cache
*/
func (d *WildcardDomain) GetResults(resolver common.DNSServers) ([]common.DNSRecordSet, error) {
	d.readLock()

	if d.fetched {
		defer d.readUnlock()
		return d.result, d.resolverErr
	}

	d.readUnlock()
	d.fetchDNSRecordsInBackground(resolver)

	// Allow the fetchDNSRecordsInBackground goroutine to start
	time.Sleep(time.Second)
	return d.GetResults(resolver)
}

/*
CreateWildcardDomainInstance returns newly initialized WildcardDomain instance. It changes the
domainName for returned WildcardDomain object to a likely non-existence subdomain of provided domain.
*/
func CreateWildcardDomainInstance(domainName string) *WildcardDomain {
	x := new(WildcardDomain)
	x.domainName = common.SanitizeDomainName(domainName)
	x.result = make([]common.DNSRecordSet, 0)
	return x
}
