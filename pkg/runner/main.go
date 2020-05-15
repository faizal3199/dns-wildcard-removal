package runner

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"github.com/faizal3199/dns-wildcard-removal/pkg/logicengine"
	"github.com/faizal3199/dns-wildcard-removal/pkg/massdns"
	"github.com/faizal3199/dns-wildcard-removal/pkg/options"
	"github.com/faizal3199/dns-wildcard-removal/pkg/output"
	"github.com/faizal3199/dns-wildcard-removal/pkg/parser"
)

/*
worker checks the DomainRecords sent by parser to be wildcard using logic engine
and then sends it to output channel.
*/
func worker(l *logicengine.LogicEngine,
	parserChan <-chan common.DomainRecords,
	outputChan chan<- common.DomainRecords,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for {
		data, more := <-parserChan

		if !more {
			return
		}

		isWildCard, err := l.IsDomainWildCard(data)

		if err != nil {
			log.Warningf("Error occurred while fetching wildcard status: %v", err)
			// don't save such domains to output
			continue
		}

		if !isWildCard {
			outputChan <- data
		}
	}
}

/*
Start is the heart of the application. It initializes all the required components and
make each component work in sync.
*/
func Start() {
	log.SetLevel(log.InfoLevel)

	args, err := options.ParseOptionsArguments()
	common.FailOnError(err, "Error while parsing options and related files")

	var wg sync.WaitGroup

	// Init channels
	parserChannel := parser.CreateChannel()
	outputChannel := output.CreateChannel()

	// Init logic engine
	logicEngine := logicengine.CreateLogicEngineInstance(args.Domain, args.Resolver)

	// Starts massdns process in background
	massdnsOutputPipe, err := massdns.StartMassdnsProcess(args.Input, args.ResolverFile)
	common.FailOnError(err, "Error initializing massdns")

	// Start parser in background
	parser.ParseAndPublishDNSRecords(massdnsOutputPipe, parserChannel)

	log.Debugf("Initializing %d workers", args.Threads)
	for i := 0; i < args.Threads; i++ {
		wg.Add(1)
		go worker(logicEngine, parserChannel, outputChannel, &wg)
	}

	// Wait for all goroutines to complete. This way any long
	// processing being done by any thread can be completed
	go func() {
		wg.Wait()

		close(outputChannel)
		log.Infoln("Closing output channel")
	}()

	// Call the blocking function. This wait until outputChannel is closed
	err = output.StartWritingOutput(args.Output, outputChannel)
	common.FailOnError(err, "Error while initializing/writing to output stream")
}
