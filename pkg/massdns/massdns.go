package massdns

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
)

/*
generateCannotOpenFileError generates an error using predefined template "cannot open file: %s"
*/
func generateCannotOpenFileError(path string) error {
	return fmt.Errorf("cannot open file: %s", path)
}

/*
checkIfFileIsOkay performs following checks
1) File exists
2) Not a directory
*/
func checkIfFileIsOkay(filePath string) bool {
	fInfo, err := os.Stat(filePath)

	if os.IsNotExist(err) {
		return false
	}

	if fInfo.IsDir() {
		return false
	}

	return true
}

/*
getInputFile check the file for given path and
if valid returns pointer to os.File object for that file
*/
func getInputFile(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	} else {
		if checkIfFileIsOkay(path) {
			fileObj, err := os.Open(path)
			return fileObj, err
		}
		return nil, generateCannotOpenFileError(path)
	}
}

/*
StartMassdnsProcess starts the massdns process in new goroutine. Returns the pointer
to output file object.
*/
func StartMassdnsProcess(inputFile string, resolverFile string) (*io.PipeReader, error) {
	if !checkIfFileIsOkay(resolverFile) {
		err := generateCannotOpenFileError(resolverFile)
		return nil, err
	}

	cmd := exec.Command("massdns", "-r", resolverFile, "-t", "A", "-o", "Snl", "--flush", "-")

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	pipeRead, pipeWrite := io.Pipe()
	cmd.Stdout = pipeWrite

	go func() {
		defer stdinPipe.Close()
		fileObj, err := getInputFile(inputFile)

		common.FailOnError(err, fmt.Sprintf("Cannot open file: %s", inputFile))

		_, err = io.Copy(stdinPipe, fileObj)
		common.FailOnError(err, "Failed to pipe input to massdns")
	}()

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	go func() {
		err = cmd.Wait()
		common.FailOnError(err, "massdns exited ungracefully")

		err = pipeWrite.Close()
		common.FailOnError(err, "Failed to close massdns output pipe")
	}()

	return pipeRead, nil
}
