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

func SanitizeDomainName(domainName string) string {
	lookupName := strings.TrimSpace(domainName)
	lookupName = strings.ToLower(lookupName)
	lookupName = strings.Trim(lookupName, ".")
	lookupName += "."

	return lookupName
}
