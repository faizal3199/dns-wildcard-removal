package common

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

/*
FailOnError checks if error is not nil and call log.Fatalf with 'msg' and 'err'
*/
func FailOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("Fatal error occurred:\nmessage: %s\nerr: %v\n", msg, err)
	}
}

/*
SanitizeDomainName performs following operation and returns result
1) Trims whitespace
2) Converts to lower case
3) Removes all extra '.'
4) Appends '.' at the end
*/
func SanitizeDomainName(domainName string) string {
	lookupName := strings.TrimSpace(domainName)
	lookupName = strings.ToLower(lookupName)
	lookupName = strings.Trim(lookupName, ".")
	lookupName += "."

	return lookupName
}
