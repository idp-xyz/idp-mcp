package observability

import (
	"strings"
	"testing"
)

func TestParseOrStart(t *testing.T) {
	tc := ParseOrStart("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", "vendor=x")
	if tc.TraceID != "0af7651916cd43dd8448eb211c80319c" || tc.State != "vendor=x" {
		t.Fatalf("%+v", tc)
	}
	child := tc.Child()
	if !strings.HasPrefix(child, "00-0af7651916cd43dd8448eb211c80319c-") || strings.Contains(child, "b7ad6b7169203331") || !strings.HasSuffix(child, "-01") {
		t.Fatal(child)
	}
	for _, bad := range []string{"", "garbage", "00-00000000000000000000000000000000-b7ad6b7169203331-01",
		"00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01", "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01"} {
		tc := ParseOrStart(bad, "vendor=x")
		if tc.State != "" || len(tc.TraceID) != 32 || tc.TraceID == "0af7651916cd43dd8448eb211c80319c" {
			t.Errorf("%q: %+v", bad, tc)
		}
	}
}
