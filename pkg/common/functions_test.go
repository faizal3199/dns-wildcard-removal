package common

import "testing"

func TestSanitizeDomainName(t *testing.T) {
	type args struct {
		domainName string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Caps",
			args: args{
				domainName: "XYZ.com",
			},
			want: "xyz.com.",
		},
		{
			name: "extra root",
			args: args{
				domainName: "XYZ.com..",
			},
			want: "xyz.com.",
		},
		{
			name: "spaces",
			args: args{
				domainName: "XYZ.com  ",
			},
			want: "xyz.com.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeDomainName(tt.args.domainName); got != tt.want {
				t.Errorf("SanitizeDomainName() = %v, want %v", got, tt.want)
			}
		})
	}
}
