package common

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
	Type  RecordTypeType
	Value RecordValueType
}

/*
DNSRecordSet is used to contain multiple records for same domain
*/
type DNSRecordSet = []DNSRecord

/*
DomainRecords contains name of the domain and it's DNS records
 */
type DomainRecords struct {
	DNSName string
	Records DNSRecordSet
}
