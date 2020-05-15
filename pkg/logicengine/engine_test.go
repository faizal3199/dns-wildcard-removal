package logicengine

import (
	"testing"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
)

func Test_LogicEngine_IsDomainWildCard(t *testing.T) {
	type fields struct {
		resolvers     common.DNSServers
		jobDomainName string
	}
	type args struct {
		domainRecord common.DomainRecords
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Test wildcard struct for xyz.myshopify.com. [CNAME]",
			fields: fields{
				resolvers: common.DNSServers{
					"1.1.1.1",
					"8.8.8.8",
				},
				jobDomainName: "myshopify.com.",
			},
			args: args{
				common.DomainRecords{
					DomainName: "xyz.myshopify.com.",
					Records: common.DNSRecordSet{
						{
							Name:  "xyz.myshopify.com.",
							Type:  "CNAME",
							Value: "shops.myshopify.com.",
						},
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Test wildcard struct for a.root-servers.net. [A]",
			fields: fields{
				resolvers: common.DNSServers{
					"1.1.1.1",
					"8.8.8.8",
				},
				jobDomainName: "root-servers.net.",
			},
			args: args{
				common.DomainRecords{
					DomainName: "a.root-servers.net.",
					Records: common.DNSRecordSet{
						{
							Name:  "a.root-servers.net.",
							Type:  "A",
							Value: "198.41.0.4",
						},
					},
				},
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "Validate against error",
			fields: fields{
				resolvers: common.DNSServers{
					"1.1.1.1",
					"8.8.8.8",
				},
				jobDomainName: "a.b.root-servers.net.",
			},
			args: args{
				common.DomainRecords{
					DomainName: "a.root-servers.net.",
					Records: common.DNSRecordSet{
						{
							Name:  "a.root-servers.net.",
							Type:  "A",
							Value: "198.41.0.4",
						},
					},
				},
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := CreateLogicEngineInstance(tt.fields.jobDomainName, tt.fields.resolvers)

			got, err := l.IsDomainWildCard(tt.args.domainRecord)

			if (err != nil) != tt.wantErr {
				t.Errorf("IsDomainWildCard() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("IsDomainWildCard() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_compareRecordsForWildCard(t *testing.T) {
	type args struct {
		currDomain   common.DNSRecordSet
		parentDomain []common.DNSRecordSet
	}
	commonParentRecord := []common.DNSRecordSet{
		{
			{
				Name:  "cname-with-a",
				Type:  "CNAME",
				Value: "a.b.c.d.",
			},
			{
				Name:  "x.y.z.",
				Type:  "A",
				Value: "1.2.3.4",
			},
		},
		{
			{
				Name:  "cname-without-a",
				Type:  "CNAME",
				Value: "a.b.c.e.",
			},
		},
		{
			{
				Name:  "only-A",
				Type:  "A",
				Value: "1.2.3.4",
			},
			{
				Name:  "only-A",
				Type:  "A",
				Value: "1.2.3.5",
			},
		},
		{
			{
				Name:  "only-A-2",
				Type:  "A",
				Value: "2.2.3.4",
			},
			{
				Name:  "only-A-2",
				Type:  "A",
				Value: "2.2.3.5",
			},
		},
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "CNAME with no A",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "CNAME",
						Value: "a.b.c.d.",
					},
				},
				parentDomain: commonParentRecord,
			},
			want: true,
		},
		{
			name: "CNAME with valid A",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "CNAME",
						Value: "a.b.c.d.",
					},
					{
						Name:  "x",
						Type:  "A",
						Value: "1.2.3.4",
					},
				},
				parentDomain: commonParentRecord,
			},
			want: true,
		},
		{
			name: "CNAME with invalid A",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "CNAME",
						Value: "a.b.c.d.",
					},
					{
						Name:  "x",
						Type:  "A",
						Value: "0.0.0.0",
					},
				},
				parentDomain: commonParentRecord,
			},
			want: true,
		},
		{
			name: "Different CNAME",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "invalid",
						Type:  "CNAME",
						Value: "invalid.com",
					},
				},
				parentDomain: commonParentRecord,
			},
			want: false,
		},
		{
			name: "A records from same group",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "1.2.3.4",
					},
					{
						Name:  "x",
						Type:  "A",
						Value: "1.2.3.5",
					},
				},
				parentDomain: commonParentRecord,
			},
			want: true,
		},
		{
			name: "A records from different group",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "1.2.3.4",
					},
					{
						Name:  "x",
						Type:  "A",
						Value: "2.2.3.5",
					},
				},
				parentDomain: commonParentRecord,
			},
			want: true,
		},
		{
			name: "different A record",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "1.2.3.4",
					},
					{
						Name:  "x",
						Type:  "A",
						Value: "3.2.3.5",
					},
				},
				parentDomain: commonParentRecord,
			},
			want: false,
		},
		{
			name: "NX Parent domain",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "0.0.0.0",
					},
				},
				parentDomain: []common.DNSRecordSet{},
			},
			want: false,
		},
		{
			name: "single group NX with matching CNAME",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "CNAME",
						Value: "a.b.c.d.",
					},
				},
				parentDomain: []common.DNSRecordSet{
					{
						{
							Name:  "rand0m",
							Type:  "CNAME",
							Value: "a.b.c.d.",
						},
					},
					{},
				},
			},
			want: true,
		},
		{
			name: "validate erroneous behaviour: parentDomain = nil",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "CNAME",
						Value: "a.b.c.d.",
					},
				},
				parentDomain: nil,
			},
			want: false,
		},
		{
			name: "validate erroneous behaviour: parentDomain = empty array",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "CNAME",
						Value: "a.b.c.d.",
					},
				},
				parentDomain: []common.DNSRecordSet{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareRecordsForWildCard(tt.args.currDomain, tt.args.parentDomain); got != tt.want {
				t.Errorf("compareRecordsForWildCard() = %v, want %v", got, tt.want)
			}
		})
	}
}
