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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := CreateLogicEngineInstance(tt.fields.jobDomainName, tt.fields.resolvers)

			got, err := l.IsDomainWildCard(tt.args.domainRecord)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsDomainWildCard() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsDomainWildCard() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_areTwoARecordsEqual(t *testing.T) {
	type args struct {
		x common.DNSRecordSet
		y common.DNSRecordSet
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Simple test for A records",
			args: args{
				x: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "1.1.1.1",
					},
				},
				y: common.DNSRecordSet{
					{
						Name:  "y",
						Type:  "A",
						Value: "1.1.1.1",
					},
				},
			},
			want: true,
		},
		{
			name: "Simple fail test for A records",
			args: args{
				x: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "1.1.1.1",
					},
				},
				y: common.DNSRecordSet{
					{
						Name:  "y",
						Type:  "A",
						Value: "1.2.1.1",
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := areTwoARecordsEqual(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("areTwoARecordsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_compareRecordsForWildCard(t *testing.T) {
	type args struct {
		currDomain   common.DNSRecordSet
		parentDomain common.DNSRecordSet
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Same CNAME target",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "CNAME",
						Value: "x.y.z.",
					},
				},
				parentDomain: common.DNSRecordSet{
					{
						Name:  "y",
						Type:  "CNAME",
						Value: "x.y.z.",
					},
				},
			},
			want: true,
		},
		{
			name: "Different CNAME target",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "CNAME",
						Value: "x.y.z.",
					},
				},
				parentDomain: common.DNSRecordSet{
					{
						Name:  "y",
						Type:  "CNAME",
						Value: "a.y.z.",
					},
				},
			},
			want: false,
		},
		{
			name: "Same CNAME with A records",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "CNAME",
						Value: "x.y.z.",
					},
					{
						Name:  "x",
						Type:  "A",
						Value: "0.0.0.0",
					},
				},
				parentDomain: common.DNSRecordSet{
					{
						Name:  "y",
						Type:  "CNAME",
						Value: "x.y.z.",
					},
					{
						Name:  "x",
						Type:  "A",
						Value: "9.9.9.9",
					},
				},
			},
			want: true,
		},
		{
			name: "Different A records",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "0.0.0.0",
					},
				},
				parentDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "1.2.3.4.",
					},
				},
			},
			want: false,
		},
		{
			name: "Same scrambled A records",
			args: args{
				currDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "0.0.0.0",
					},
					{
						Name:  "x",
						Type:  "A",
						Value: "1.2.3.4.",
					},
				},
				parentDomain: common.DNSRecordSet{
					{
						Name:  "x",
						Type:  "A",
						Value: "1.2.3.4.",
					},
					{
						Name:  "x",
						Type:  "A",
						Value: "0.0.0.0",
					},
				},
			},
			want: true,
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
					{
						Name:  "x",
						Type:  "A",
						Value: "1.2.3.4.",
					},
				},
				parentDomain: common.DNSRecordSet{},
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
