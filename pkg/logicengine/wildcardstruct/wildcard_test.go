package wildcardstruct

import (
	"reflect"
	"testing"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
)

func Test_wildcardDomain_GetResults(t *testing.T) {
	type fields struct {
		DomainName string
	}
	type args struct {
		resolver common.DNSServers
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    common.DNSRecordSet
		wantErr bool
	}{
		{
			name: "Fetch records for dns-test.faizalhasanwala.me.",
			fields: fields{
				DomainName: "dns-test.faizalhasanwala.me.",
			},
			args: args{
				resolver: common.DNSServers{
					"1.1.1.1",
					"8.8.8.8",
				},
			},
			want: common.DNSRecordSet{
				{
					Name:  "dns-test.faizalhasanwala.me.",
					Type:  "A",
					Value: "127.0.0.1",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := CreateWildcardDomainInstance(tt.fields.DomainName)

			tt.want[0].Name = NonExistingLabel + "." + tt.want[0].Name

			got, err := d.GetResults(tt.args.resolver)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetResults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetResults() got = %v, want %v", got, tt.want)
			}
		})
	}
}
