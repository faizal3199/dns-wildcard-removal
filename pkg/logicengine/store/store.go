package store

import (
	"sync"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"

	log "github.com/sirupsen/logrus"

	"github.com/faizal3199/dns-wildcard-removal/pkg/logicengine/wildcardstruct"
)

/*
Store caches WildcardDomain objects and exposes a thread safe function to access them
*/
type Store struct {
	cache map[string]*wildcardstruct.WildcardDomain
	mutex sync.Mutex
}

func (c *Store) lock() {
	c.mutex.Lock()
}

func (c *Store) unlock() {
	c.mutex.Unlock()
}

/*
GetOrCreateDomainObject returns the domain object is present in cache or creates and return
the new object. created is true if new object is created otherwise false
*/
func (c *Store) GetOrCreateDomainObject(domainName string) (value *wildcardstruct.WildcardDomain, created bool) {
	defer c.unlock()
	c.lock()

	// Alter domain name to match valid format
	lookupName := common.SanitizeDomainName(domainName)

	cachedObject := c.cache[lookupName]

	if cachedObject == nil {
		log.Debugf("Creating new wildcardDomain Object for %s", lookupName)
		newObject := wildcardstruct.CreateWildcardDomainInstance(lookupName)

		c.cache[lookupName] = newObject

		return newObject, true
	}

	return cachedObject, false
}

/*
CreateStoreInstance returns a newly initialized store instance.
*/
func CreateStoreInstance() *Store {
	x := new(Store)
	x.cache = map[string]*wildcardstruct.WildcardDomain{}
	return x
}
