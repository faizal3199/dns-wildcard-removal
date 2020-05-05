package parser

import (
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/faizal3199/dns-wildcard-removal/pkg/common"
)

func TestParseAndPublishDNSRecords(t *testing.T) {
	t.Parallel()

	reader, writer := io.Pipe()
	c := make(chan common.DomainRecords)

	expectedRecord := common.DomainRecords{
		DNSName: "cname.dns-test.faizalhasanwala.me.",
		Records: common.DNSRecordSet{
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
	}

	t.Run("Parser Test", func(t *testing.T) {
		ParseAndPublishDNSRecords(reader, c)

		go func() {
			// Simulate some delay in reading(as in processing overhead)
			time.Sleep(2 * time.Second)
			_, _ = writer.Write([]byte(expectedRecord.Records.String() + "\n"))
			_ = writer.Close()
		}()

		for {
			data, more := <-c
			if !more {
				break
			}

			if !reflect.DeepEqual(data, expectedRecord) {
				t.Errorf("ParseAndPublishDNSRecords() = %v, want %v", data, expectedRecord)
				return
			}
		}
	})
}
