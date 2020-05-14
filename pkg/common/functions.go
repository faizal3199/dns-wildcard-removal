package common

import (
	log "github.com/sirupsen/logrus"
)

func FailOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("Fatal error occured:\nmessage: %s\nerr: %v\n", msg, err)
	}
}
