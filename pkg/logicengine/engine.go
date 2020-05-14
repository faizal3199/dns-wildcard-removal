package logicengine

import (
	"sort"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"github.com/faizal3199/dns-wildcard-removal/pkg/dnsengine"
	"github.com/faizal3199/dns-wildcard-removal/pkg/logicengine/store"
)

type LogicEngine struct {
	resolvers     common.DNSServers
	jobDomainName string
	store         store.Store
}

/*
IsDomainWildCard check if provided domain is wildcard. This will check upto all parent domains until
dnsengine.GetParentDomain returns no new domain(i.e. returns with error). function returns any error encountered
by dns engine during fetching
*/
func (l *LogicEngine) IsDomainWildCard(domainRecord common.DomainRecords) (bool, error) {
	currentDomain := domainRecord.DomainName

	for {
		parentDomain, err := dnsengine.GetParentDomain(currentDomain, l.jobDomainName)
		// getParentDomain err
		// No more parent domain
		if err != nil {
			return false, nil
		}

		parentDomainObject, _ := l.store.GetOrCreateDomainObject(parentDomain)
		parentDomainRecords, err := parentDomainObject.GetResults(l.resolvers)
		// getResults err
		// some error occurred during fetching results
		if err != nil {
			return false, err
		}

		if compareRecordsForWildCard(domainRecord.Records, parentDomainRecords) {
			return true, nil
		}

		currentDomain = parentDomain
	}
}

func areTwoArraysEqual(a1, a2 []string) bool {
	sort.Strings(a1)
	sort.Strings(a2)
	if len(a1) == len(a2) {
		for i, v := range a1 {
			if v != a2[i] {
				return false
			}
		}
	} else {
		return false
	}
	return true
}

func getArrayOfARecords(x common.DNSRecordSet) []string {
	arrX := make([]string, 0)
	for i := 0; i < len(x); i++ {
		arrX = append(arrX, x[i].Value)
	}
	return arrX
}

func areTwoARecordsEqual(x, y common.DNSRecordSet) bool {
	arrX := getArrayOfARecords(x)
	arrY := getArrayOfARecords(y)

	return areTwoArraysEqual(arrX, arrY)
}

/*
compareRecordsForWildCard matched currDomain's and parentDomain's records for static wildcard detection.
Returns true if current domain matches for wildcard else false.


Following is the logic for wildcard match:

CNAME: if both are CNAME and there target matches.

A: if both records starts with A records and has same IPs(unordered/ordered).

All other cases result in no wildcard deduction including parentDomain being NX domain(empty record set)
*/
func compareRecordsForWildCard(currDomain common.DNSRecordSet, parentDomain common.DNSRecordSet) bool {
	// NX Domain
	if len(parentDomain) == 0 {
		return false
	}

	// currDomain can't be NX domain because massdns provides the data

	// Ensure both are of same type
	if currDomain[0].Type != parentDomain[0].Type {
		return false
	}

	if currDomain[0].Type == "A" {
		return areTwoARecordsEqual(currDomain, parentDomain)
	} else if currDomain[0].Type == "CNAME" {
		// Only compare CNAME targets
		return currDomain[0].Value == parentDomain[0].Value
	} else {
		return false
	}
}

/*
CreateLogicEngineInstance returns a newly initialized object of LogicEngine.
*/
func CreateLogicEngineInstance(domainName string, resolvers common.DNSServers) *LogicEngine {
	x := new(LogicEngine)
	x.resolvers = resolvers
	x.jobDomainName = domainName
	x.store = *store.CreateStoreInstance()
	return x
}
