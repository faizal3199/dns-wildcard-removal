package common

import "log"

func FailOnError(err error, msg string) {
	if err != nil {
		log.Fatalln(msg)
	}
}
