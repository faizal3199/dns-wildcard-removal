package wildcardstruct

import (
	"strings"
	"sync"
	"time"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"github.com/faizal3199/dns-wildcard-removal/pkg/dnsengine"
)

type WildcardDomain struct {
	domainName  string
	mutex       sync.RWMutex
	result      common.DNSRecordSet
	resolverErr error
	fetched     bool
}

const (
	NonExistingLabel = "n0n-exist3nc3-l4b3l-bip-b0p-bip-b0p-1-0-1-1-0-1"
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
		res, err := dnsengine.GetDNSRecords(resolvers, d.domainName)
		d.fetched = true
		d.resolverErr = err

		if err == nil {
			d.result = res
		} else {
			d.result = nil
		}
	}()
}

/*
GetResults checks if records are already fetched if so return else call fetchDNSRecordsInBackground
to fetch records and then recursively call GetResults. GetResults acquires read lock before checking
in cache
*/
func (d *WildcardDomain) GetResults(resolver common.DNSServers) (common.DNSRecordSet, error) {
	d.readLock()

	if d.fetched {
		defer d.readUnlock()
		return d.result, d.resolverErr
	} else {
		d.readUnlock()
		d.fetchDNSRecordsInBackground(resolver)

		// Allow the fetchDNSRecordsInBackground goroutine to start
		time.Sleep(time.Second)
		return d.GetResults(resolver)
	}
}

/*
CreateWildcardDomainInstance returns newly initialized WildcardDomain instance. It changes the
domainName for returned WildcardDomain object to a likely non-existence subdomain of provided domain.
 */
func CreateWildcardDomainInstance(domainName string) *WildcardDomain {
	x := new(WildcardDomain)
	tmp := strings.Trim(domainName, ".")
	tmp = NonExistingLabel + "." + tmp + "."
	x.domainName = tmp
	return x
}
