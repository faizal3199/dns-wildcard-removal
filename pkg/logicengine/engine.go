package logicengine

import (
	mapset "github.com/deckarep/golang-set"
	log "github.com/sirupsen/logrus"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"github.com/faizal3199/dns-wildcard-removal/pkg/dnsengine"
	"github.com/faizal3199/dns-wildcard-removal/pkg/logicengine/store"
)

/*
LogicEngine exposes function to check if a domain is wildcard. All the complexities are handled
by it.
*/
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

/*
How is mapset created?
1) If DNSRecordSet is of CNAME type. Then only CNAME target value is used for mapset
2) If DNSRecordSet is of A type. Then all A values are used for mapset
*/
func getSetFromRecords(x common.DNSRecordSet) mapset.Set {
	tempSet := mapset.NewSet()

	if x == nil || len(x) == 0 {
		return tempSet
	}

	// If CNAME : only use target value
	if x[0].Type == "CNAME" {
		tempSet.Add(x[0].Value)
	} else {
		// If A : use all values
		for _, record := range x {
			tempSet.Add(record.Value)
		}
	}

	return tempSet
}

func getSetFromRecordsArray(x []common.DNSRecordSet) mapset.Set {
	tempSet := mapset.NewSet()

	for _, recordSet := range x {
		tempSet = tempSet.Union(getSetFromRecords(recordSet))
	}

	return tempSet
}

/*
compareRecordsForWildCard matched currDomain's and parentDomain's records for static wildcard detection.
Returns true if current domain matches for wildcard else false.


Following is the logic for wildcard match:

The function creates a mapset of records for currDomain(regardless of CNAME or A type). The function then checks
if the newly created mapset is subset of parentDomain's mapset.

How is mapset created?
1) If DNSRecordSet is of CNAME type. Then only CNAME target value is used for mapset
2) If DNSRecordSet is of A type. Then all A values are used for mapset
*/
func compareRecordsForWildCard(currDomain common.DNSRecordSet, parentDomain []common.DNSRecordSet) bool {
	// NX Domain parentDomain
	areAllRecordsNX := true
	for _, recordSet := range parentDomain {
		if recordSet != nil && len(recordSet) != 0 {
			areAllRecordsNX = false
			break
		}
	}

	if areAllRecordsNX {
		return false
	}

	// currDomain can't have zero records because massdns provides the data
	if len(currDomain) == 0 {
		log.Fatalf("Invalid record used for comparison: %v", currDomain)
	}

	currDomainSet := getSetFromRecords(currDomain)
	parentDomainSet := getSetFromRecordsArray(parentDomain)

	return currDomainSet.IsSubset(parentDomainSet)
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
