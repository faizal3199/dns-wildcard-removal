package dnshandler

import (
	"io/ioutil"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
)

func writeToTempFileAndLogErr(data string, t *testing.T) (inputFile *os.File, errEncountered bool) {
	inputFile, err := ioutil.TempFile("", "rand0m_tmp_*")
	if err != nil {
		t.Errorf("ResolveFromInputFile(): Encountered error: %v", err)
		return nil, true
	}

	_, err = inputFile.Write([]byte(data))
	errEncountered = err != nil

	if errEncountered {
		t.Errorf("ResolveFromInputFile(): Encountered error: %v", err)
	}

	return
}

func TestResolveFromInputFile(t *testing.T) {
	type args struct {
		inputFile string
		resolvers common.DNSServers
	}

	t.Parallel()

	inputData := "cname.dns-test.faizalhasanwala.me"
	expectedOutput := common.DomainRecords{
		DomainName: "cname.dns-test.faizalhasanwala.me.",
		Records: common.DNSRecordSet{
			{
				Name:  "cname.dns-test.faizalhasanwala.me.",
				Type:  "CNAME",
				Value: "a.root-servers.net.",
			},
			{
				Name:  "a.root-servers.net.",
				Type:  "A",
				Value: "198.41.0.4",
			},
		},
	}
	resolvers := common.DNSServers{"1.1.1.1", "8.8.8.8"}

	t.Run("Check output: file", func(t *testing.T) {
		inputFile, errEnc := writeToTempFileAndLogErr(inputData, t)
		if errEnc {
			return
		}
		defer os.Remove(inputFile.Name())

		c := CreateChannel()
		err := ResolveFromInputFile(inputFile.Name(), resolvers, c)

		if err != nil {
			t.Errorf("ResolveFromInputFile(): Encountered error: %v", err)
			return
		}

		res, more := <-c

		// It should return results & true. If successful
		if !more {
			t.Errorf("ResolveFromInputFile(): Returned no results")
			return
		}

		if !reflect.DeepEqual(res, expectedOutput) {
			t.Errorf("GetDNSRecords() = %v, want %v", res, expectedOutput)
		}

		res, more = <-c
		// It should now return nil & false. As channel should be closed
		if more {
			t.Errorf("ResolveFromInputFile(): Expected channel to be closed. Sent: %v", res)
			return
		}
	})

	t.Run("Check output: stdin", func(t *testing.T) {
		inputFile, errEnc := writeToTempFileAndLogErr(inputData, t)
		if errEnc {
			return
		}
		defer os.Remove(inputFile.Name())

		// Prepare input for swap
		_, err := inputFile.Seek(0, 0)
		if err != nil {
			t.Errorf("ResolveFromInputFile(): Encountered error: %v", err)
			return
		}

		// Swap stdin
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		os.Stdin = inputFile

		c := CreateChannel()

		err = ResolveFromInputFile(inputFile.Name(), resolvers, c)

		if err != nil {
			t.Errorf("ResolveFromInputFile(): Encountered error: %v", err)
			return
		}

		res, more := <-c

		// It should return results & true. If successful
		if !more {
			t.Errorf("ResolveFromInputFile(): Returned no results")
			return
		}

		if !reflect.DeepEqual(res, expectedOutput) {
			t.Errorf("GetDNSRecords() = %v, want %v", res, expectedOutput)
		}

		res, more = <-c
		// It should now return nil & false. As channel should be closed
		if more {
			t.Errorf("ResolveFromInputFile(): Expected channel to be closed. Sent: %v", res)
			return
		}
	})
}

func Test_checkIfFileIsOkay(t *testing.T) {
	type args struct {
		filePath string
	}

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("Skipping in windows")
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Non Existent file/directory",
			args: args{
				filePath: "/xyz/abc",
			},
			want: false,
		},
		{
			name: "Existent Directory",
			args: args{
				filePath: "/",
			},
			want: false,
		},
		{
			name: "Existent file",
			args: args{
				filePath: "/etc/hosts",
			},
			want: true,
		},
		{
			name: "Existent unreadable file",
			args: args{
				filePath: "/etc/shadow",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkIfFileIsOkay(tt.args.filePath); got != tt.want {
				t.Errorf("checkIfFileIsOkay() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_generateCannotOpenFileError(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Any input",
			args: args{
				path: "*",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := generateCannotOpenFileError(tt.args.path); (err != nil) != tt.wantErr {
				t.Errorf("generateCannotOpenFileError() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getInputFile(t *testing.T) {
	type args struct {
		path string
	}

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("Skipping in windows")
	}

	tests := []struct {
		name     string
		args     args
		wantPath string
		wantErr  bool
	}{
		{
			name: "Input file: /etc/hosts",
			args: args{
				path: "/etc/hosts",
			},
			wantPath: "/etc/hosts",
			wantErr:  false,
		},
		{
			name: "Input file: stdin",
			args: args{
				path: "-",
			},
			wantPath: "-",
			wantErr:  false,
		},
		{
			name: "Input file: directory",
			args: args{
				path: "/",
			},
			wantPath: "/",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getInputFile(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("getInputFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			var want *os.File

			if tt.wantPath == "-" {
				want = os.Stdin
			} else {
				want, _ = os.Open(tt.wantPath)
			}

			gotStat, _ := got.Stat()
			wantStat, _ := want.Stat()

			if !reflect.DeepEqual(gotStat, wantStat) {
				t.Errorf("getInputFile() = %v, want %v", gotStat, wantStat)
			}
		})
	}
}
