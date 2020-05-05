package common

import "testing"

func TestDNSRecordSet_String(t *testing.T) {
	tests := []struct {
		name string
		d    DNSRecordSet
		want string
	}{
		{
			name: "Convert DNSRecordSet into string",
			d: DNSRecordSet{
				{
					Name:  "b.example.com.",
					Type:  "CNAME",
					Value: "a.example.com.",
				},
				{
					Name:  "a.example.com.",
					Type:  "A",
					Value: "0.0.0.0",
				},
			},
			want: "b.example.com. CNAME a.example.com.\na.example.com. A 0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNSRecord_String(t *testing.T) {
	type fields struct {
		Name  string
		Type  RecordTypeType
		Value RecordValueType
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Convert DNSRecord into string",
			fields: fields{
				Name:  "example.com.",
				Type:  "A",
				Value: "0.0.0.0",
			},
			want: "example.com. A 0.0.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := DNSRecord{
				Name:  tt.fields.Name,
				Type:  tt.fields.Type,
				Value: tt.fields.Value,
			}
			if got := d.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
