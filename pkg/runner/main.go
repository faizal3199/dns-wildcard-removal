package runner

import (
	"sync"

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
	wg.Add(1)
	defer wg.Done()

	for {
		data, more := <-parserChan

		if !more {
			return
		}

		isWildCard, err := l.IsDomainWildCard(data)
		common.FailOnError(err, "Error occurred during resolving a domain")

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

	for i := 0; i < args.Threads; i++ {
		go worker(logicEngine, parserChannel, outputChannel, &wg)
	}

	// Wait for all goroutines to complete. This way any long
	// processing being done by any thread can be completed
	go func() {
		wg.Wait()
		close(outputChannel)
	}()

	// Call the blocking function. This wait until outputChannel is closed
	err = output.StartWritingOutput(args.Output, outputChannel)
	common.FailOnError(err, "Error while initializing/writing to output stream")
}
