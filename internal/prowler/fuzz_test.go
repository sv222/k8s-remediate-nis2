package prowler

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, n := range []string{"legacy.json", "ocsf.json", "asff.json", "legacy_missing_status.json", "object_wrapper.json"} {
		data, err := os.ReadFile("testdata/" + n)
		if err != nil {
			f.Fatal(err)
		}
		if len(data) < 8192 {
			f.Add(data)
		}
		var elems []json.RawMessage
		if json.Unmarshal(data, &elems) == nil {
			for _, e := range elems {
				f.Add(append(append([]byte("["), e...), ']'))
			}
		}
	}
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"CheckID":"x","Status":"FAIL","Muted":true,"AccountId":"1"}]`))
	f.Add([]byte(`[{"metadata":{"event_code":"c"},"status_code":"FAIL","status":"Suppressed","status_id":3,"finding_info":{},"cloud":{"account":{"uid":"1"}}}]`))
	f.Add([]byte(`[{"finding_info":{},"status_code":"fail"},{"CheckID":"a"},null,1,"x"]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := Parse(data, "f.json")
		if err != nil {
			if got != nil {
				t.Fatalf("findings returned together with an error: %v", err)
			}
			return
		}
		if len(got) == 0 {
			t.Fatal("no error and no findings")
		}
		for _, fd := range got {
			if fd.Scanner != "prowler" || fd.CheckID == "" || fd.Status == "" {
				t.Fatalf("incomplete finding: %+v", fd)
			}
			if fd.Status != strings.TrimSpace(fd.Status) {
				t.Fatalf("status keeps spaces: %q", fd.Status)
			}
		}
		again, err := Parse(data, "f.json")
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatal("parse is not deterministic")
		}
	})
}
