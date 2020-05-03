package massdns

import (
	"bytes"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestStartMassdnsProcess(t *testing.T) {
	t.Parallel()

	expectedOutput := "cname.dns-test.faizalhasanwala.me. CNAME a.root-servers.net.\n"
	expectedOutput += "a.root-servers.net. A 198.41.0.4\n"
	expectedOutput += "\n"

	t.Run("Check output: immediate", func(t *testing.T) {
		inputFile, _ := ioutil.TempFile("", "massdns_input_*")
		defer os.Remove(inputFile.Name())
		_, err := inputFile.Write([]byte("cname.dns-test.faizalhasanwala.me"))
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		resolverFile, _ := ioutil.TempFile("", "resolver_file_*")
		defer os.Remove(resolverFile.Name())
		_, err = resolverFile.Write([]byte("1.1.1.1"))
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		outputFile, _ := StartMassdnsProcess(inputFile.Name(), resolverFile.Name())
		buff := new(bytes.Buffer)

		_, err = buff.ReadFrom(outputFile)
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		output := buff.String()

		if output != expectedOutput {
			t.Errorf("StartMassdnsProcess() got = `\n%s\n`, want `\n%s\n`", output, expectedOutput)
		}
	})

	t.Run("Check output: delayed", func(t *testing.T) {
		inputFile, _ := ioutil.TempFile("", "massdns_input_*")
		defer os.Remove(inputFile.Name())
		_, err := inputFile.Write([]byte("cname.dns-test.faizalhasanwala.me"))
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		resolverFile, _ := ioutil.TempFile("", "resolver_file_*")
		defer os.Remove(resolverFile.Name())
		_, err = resolverFile.Write([]byte("1.1.1.1"))
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		outputFile, _ := StartMassdnsProcess(inputFile.Name(), resolverFile.Name())

		time.Sleep(3 * time.Second)

		buff := new(bytes.Buffer)

		_, err = buff.ReadFrom(outputFile)
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		output := buff.String()

		if output != expectedOutput {
			t.Errorf("StartMassdnsProcess() got = `\n%s\n`, want `\n%s\n`", output, expectedOutput)
		}

	})

	t.Run("Check output: stdin input", func(t *testing.T) {
		inputFile, _ := ioutil.TempFile("", "massdns_input_*")
		defer os.Remove(inputFile.Name())
		_, err := inputFile.Write([]byte("cname.dns-test.faizalhasanwala.me"))
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		resolverFile, _ := ioutil.TempFile("", "resolver_file_*")
		defer os.Remove(resolverFile.Name())
		_, err = resolverFile.Write([]byte("1.1.1.1"))
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		_, err = inputFile.Seek(0, 0)
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		// Swap stdin
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		os.Stdin = inputFile

		outputFile, _ := StartMassdnsProcess("-", resolverFile.Name())

		buff := new(bytes.Buffer)

		_, err = buff.ReadFrom(outputFile)
		if err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

		output := buff.String()

		if output != expectedOutput {
			t.Errorf("StartMassdnsProcess() got = `\n%s\n`, want `\n%s\n`", output, expectedOutput)
		}

		if err := inputFile.Close(); err != nil {
			t.Errorf("StartMassdnsProcess(): Encountered error: %v", err)
			return
		}

	})
}

func Test_checkIfFileIsOkay(t *testing.T) {
	type args struct {
		filePath string
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
