package store

import (
	"reflect"
	"testing"
)

func TestStore_GetOrCreateDomainObject(t *testing.T) {
	t.Run("Verify store's cache", func(t *testing.T) {
		DomainName := "xyz.com"

		c := CreateStoreInstance()
		gotValue1, gotCreated1 := c.GetOrCreateDomainObject(DomainName)

		if !gotCreated1 {
			t.Errorf("GetOrCreateDomainObject() gotCreated1 = %v, want %v", gotCreated1, true)
		}

		gotValue2, gotCreated2 := c.GetOrCreateDomainObject(DomainName)

		if gotCreated2 {
			t.Errorf("GetOrCreateDomainObject() gotCreated2 = %v, want %v", gotCreated1, false)
		}

		if !reflect.DeepEqual(gotValue1, gotValue2) {
			t.Errorf("GetOrCreateDomainObject() gotValue1 = %v, gotValue2 = %v, want both equal",
				gotValue1, gotValue2)
		}
	})
}
