package common

import "log"

func FailOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("Fatal error occured:\nmessage: %s\nerr: %v\n", msg, err)
	}
}
