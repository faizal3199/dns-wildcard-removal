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

	t.Parallel()

	tests := []struct {
		name     string
		fields   fields
		args     args
		wantBase common.DNSRecordSet
		wantErr  bool
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
			wantBase: common.DNSRecordSet{
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

			got, err := d.GetResults(tt.args.resolver)

			// Modify to match random domain name
			want := make([]common.DNSRecordSet, 0)
			for _, records := range got {
				copyOfWantBase := make([]common.DNSRecord, len(tt.wantBase))
				// Copy to avoid all records pointing to same base
				copy(copyOfWantBase, tt.wantBase)

				copyOfWantBase[0].Name = records[0].Name
				want = append(want, copyOfWantBase)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("GetResults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != numberOfTest {
				t.Errorf("GetResults() len(got) = %d, len(want) %d", len(got), numberOfTest)
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("GetResults() got = %v, want %v", got, want)
			}
		})
	}
}
