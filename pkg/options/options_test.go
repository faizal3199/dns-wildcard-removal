package options

import (
	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func writeToTempFile(data string) (*os.File, error) {
	inputFile, err := ioutil.TempFile("", "rand0m_tmp_*")

	if err != nil {
		return nil, err
	}
	_, err = inputFile.Write([]byte(data))

	return inputFile, err
}

func Test_parseListOfResolversFromList(t *testing.T) {
	type args struct {
		fileData string
	}
	tests := []struct {
		name    string
		args    args
		want    common.DNSServers
		wantErr bool
	}{
		{
			name: "Verify resolver file's parsing",
			args: args{
				fileData: "1.1.1.1\n8.8.8.8\n#0.0.0.0",
			},
			want:    common.DNSServers{"1.1.1.1", "8.8.8.8"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := writeToTempFile(tt.args.fileData)
			defer os.Remove(file.Name())
			if err != nil {
				t.Errorf("parseListOfResolversFromList(): Encountered error: %v", err)
				return
			}

			got, err := parseListOfResolversFromList(file.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("parseListOfResolversFromList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseListOfResolversFromList() got = %v, want %v", got, tt.want)
			}
		})
	}
}
