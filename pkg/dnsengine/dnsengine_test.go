package dnsengine_test

import (
	"reflect"
	"testing"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
	"github.com/faizal3199/dns-wildcard-removal/pkg/dnsengine"
)

func TestGetDNSRecords(t *testing.T) {
	type args struct {
		resolvers common.DNSServers
		domain    common.DomainType
	}
	tests := []struct {
		name    string
		args    args
		want    common.DNSRecordSet
		wantErr bool
	}{
		{
			name: "Test for A record",
			args: args{
				resolvers: common.DNSServers{"1.1.1.1", "8.8.8.8"},
				domain:    "a.root-servers.net",
			},
			want: common.DNSRecordSet{
				{
					Type:  "A",
					Value: "198.41.0.4",
				},
			},
			wantErr: false,
		},
		{
			name: "Test for CNAME record",
			args: args{
				resolvers: common.DNSServers{"1.1.1.1", "8.8.8.8"},
				domain:    "cname.dns-test.faizalhasanwala.me",
			},
			want: common.DNSRecordSet{
				{
					Type:  "CNAME",
					Value: "a.root-servers.net.",
				},
				{
					Type:  "A",
					Value: "198.41.0.4",
				},
			},
			wantErr: false,
		},
		{
			name: "Test for CNAME only record",
			args: args{
				resolvers: common.DNSServers{"1.1.1.1", "8.8.8.8"},
				domain:    "cname2.dns-test.faizalhasanwala.me",
			},
			want: common.DNSRecordSet{
				{
					Type:  "CNAME",
					Value: "xx.root-servers.net.",
				},
			},
			wantErr: false,
		},
		{
			name: "Test for NX domain",
			args: args{
				resolvers: common.DNSServers{"1.1.1.1", "8.8.8.8"},
				domain:    "nx.root-servers.net",
			},
			want:    common.DNSRecordSet{},
			wantErr: false,
		},
		{
			name: "Test for Invalid DNS resolver",
			args: args{
				resolvers: common.DNSServers{"1.2.3.4"},
				domain:    "nx.dns-test.faizalhasanwala.me",
			},
			want:    nil,
			wantErr: true,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsengine.GetDNSRecords(tt.args.resolvers, tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDNSRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetDNSRecords() = %v, want %v", got, tt.want)
			}
		})
	}
}
