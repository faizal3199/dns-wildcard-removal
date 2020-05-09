package store

import (
	"github.com/faizal3199/dns-wildcard-removal/pkg/logicengine/wildcardstruct"
	"sync"
)

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

	cachedObject := c.cache[domainName]

	if cachedObject == nil {
		newObject := wildcardstruct.CreateWildcardDomainInstance(domainName)

		c.cache[domainName] = newObject

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
