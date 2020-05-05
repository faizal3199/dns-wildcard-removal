package common

import (
	"fmt"
	"strings"
)

/*
RecordTypeType to represent type of DNS record types
*/
type RecordTypeType = string

/*
RecordValueType to represent value of a DNS record
*/
type RecordValueType = string

/*
DomainType to represent domain's type
*/
type DomainType = string

/*
IPAddressType is used to type of IP Address
*/
type IPAddressType = string

/*
DNSServers is used to reperesnt a list of DNS servers
*/
type DNSServers []IPAddressType

/*
Various constants related to DNS record types
*/
const (
	TypeA     = "A"
	TypeNS    = "NS"
	TypeCNAME = "CNAME"
)

/*
DNSRecord represents a complete DNS record(except TTL)
*/
type DNSRecord struct {
	Name  string
	Type  RecordTypeType
	Value RecordValueType
}

/*
String returns string format of DNS record
*/
func (d DNSRecord) String() string {
	return fmt.Sprintf("%s %s %s", d.Name, d.Type, d.Value)
}

/*
DNSRecordSet is used to contain multiple records for same domain
*/
type DNSRecordSet []DNSRecord

/*
String returns string format of DNS record
*/
func (d DNSRecordSet) String() string {
	returnVal := ""
	for i := 0; i < len(d); i++ {
		returnVal += d[i].String() + "\n"
	}

	return strings.TrimSpace(returnVal)
}

/*
DomainRecords contains name of the domain and it's DNS records
*/
type DomainRecords struct {
	DomainName string
	Records DNSRecordSet
}
