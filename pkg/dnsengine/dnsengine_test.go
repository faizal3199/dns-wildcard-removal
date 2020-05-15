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
				domain:    "a.root-servers.net.",
			},
			want: common.DNSRecordSet{
				{
					Name:  "a.root-servers.net.",
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
				domain:    "cname.dns-test.faizalhasanwala.me.",
			},
			want: common.DNSRecordSet{
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
			wantErr: false,
		},
		{
			name: "Test for CNAME only record",
			args: args{
				resolvers: common.DNSServers{"1.1.1.1", "8.8.8.8"},
				domain:    "cname2.dns-test.faizalhasanwala.me.",
			},
			want: common.DNSRecordSet{
				{
					Name:  "cname2.dns-test.faizalhasanwala.me.",
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
				domain:    "nx.root-servers.net.",
			},
			want:    common.DNSRecordSet{},
			wantErr: false,
		},
		{
			name: "Test for Invalid DNS resolver",
			args: args{
				resolvers: common.DNSServers{"1.2.3.4"},
				domain:    "nx.dns-test.faizalhasanwala.me.",
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

func TestGetParentDomain(t *testing.T) {
	t.Parallel()

	type args struct {
		domain    string
		jobDomain string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "Domain name with spaces",
			args: args{
				domain:    " xyz.a.root-servers.net ",
				jobDomain: "root-server.net.",
			},
			want:    []string{"root-servers.net.", "a.root-servers.net."},
			wantErr: false,
		},
		{
			name: "Domain name with extra dots",
			args: args{
				domain:    "xyz.a.root-servers.net.",
				jobDomain: "root-servers.net.",
			},
			want:    []string{"root-servers.net.", "a.root-servers.net."},
			wantErr: false,
		},
		{
			name: "Domain name with extra dots and spaces",
			args: args{
				domain:    " xyz.a.root-servers.net. ",
				jobDomain: "root-servers.net.",
			},
			want:    []string{"root-servers.net.", "a.root-servers.net."},
			wantErr: false,
		},
		{
			name: "Level 3",
			args: args{
				domain:    "a.root-servers.net",
				jobDomain: "root-servers.net.",
			},
			want:    []string{"root-servers.net."},
			wantErr: false,
		},
		{
			name: "Level 2",
			args: args{
				domain:    "root-servers.net",
				jobDomain: "root-servers.net.",
			},
			want:    []string{"root-servers.net."},
			wantErr: false,
		},
		{
			name: "Level 5",
			args: args{
				domain:    "1.2.3.root-servers.net",
				jobDomain: "root-servers.net.",
			},
			want:    []string{"root-servers.net.", "3.root-servers.net.", "2.3.root-servers.net."},
			wantErr: false,
		},
		{
			name: "Validate against error",
			args: args{
				domain:    "net",
				jobDomain: "root-servers.net.",
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsengine.GetParentDomain(tt.args.domain, tt.args.jobDomain)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetParentDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetParentDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
