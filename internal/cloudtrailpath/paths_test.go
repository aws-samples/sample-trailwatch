package cloudtrailpath

import (
	"reflect"
	"testing"
	"time"
)

func TestDatePrefixesOrganizationLayouts(t *testing.T) {
	date := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)
	got := DatePrefixes(MultiAccountMode, "o-example", "123456789012", "us-east-1", date)
	want := []string{
		"AWSLogs/o-example/123456789012/CloudTrail/us-east-1/2026/07/26/",
		"o-example/AWSLogs/o-example/123456789012/CloudTrail/us-east-1/2026/07/26/",
		"o-example/AWSLogs/123456789012/CloudTrail/us-east-1/2026/07/26/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DatePrefixes() = %#v, want %#v", got, want)
	}
}

func TestDatePrefixesSingleAccount(t *testing.T) {
	date := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)
	got := DatePrefixes("single", "", "123456789012", "ap-south-1", date)
	want := []string{"AWSLogs/123456789012/CloudTrail/ap-south-1/2026/07/26/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DatePrefixes() = %#v, want %#v", got, want)
	}
}

func TestAccountDiscoveryPrefixes(t *testing.T) {
	got := AccountDiscoveryPrefixes("o-example")
	want := []string{
		"AWSLogs/o-example/",
		"o-example/AWSLogs/o-example/",
		"o-example/AWSLogs/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AccountDiscoveryPrefixes() = %#v, want %#v", got, want)
	}
}

func TestLocalRegionDirsOrganizationLayouts(t *testing.T) {
	got := LocalRegionDirs("/data", "logs", MultiAccountMode, "o-example", "123456789012", "us-east-1")
	want := []string{
		"/data/s3/logs/AWSLogs/o-example/123456789012/CloudTrail/us-east-1",
		"/data/s3/logs/o-example/AWSLogs/o-example/123456789012/CloudTrail/us-east-1",
		"/data/s3/logs/o-example/AWSLogs/123456789012/CloudTrail/us-east-1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LocalRegionDirs() = %#v, want %#v", got, want)
	}
}

func TestLocalQueryRoot(t *testing.T) {
	if got := LocalQueryRoot("/data", "logs", MultiAccountMode, "o-example", "123456789012", "us-east-1"); got != "/data/s3/logs/" {
		t.Fatalf("multi-account LocalQueryRoot() = %q", got)
	}
	if got := LocalQueryRoot("/data", "logs", "single", "", "123456789012", "us-east-1"); got != "/data/s3/logs/AWSLogs/123456789012/CloudTrail/us-east-1/" {
		t.Fatalf("single-account LocalQueryRoot() = %q", got)
	}
}
