package kubebench

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	data, err := os.ReadFile("testdata/bench.json")
	if err != nil {
		f.Fatal(err)
	}
	if len(data) < 8192 {
		f.Add(data)
	}
	var doc struct {
		Controls []struct {
			ID      string            `json:"id"`
			Version string            `json:"version"`
			Tests   []json.RawMessage `json:"tests"`
		} `json:"Controls"`
	}
	if json.Unmarshal(data, &doc) == nil {
		for _, c := range doc.Controls {
			for _, tst := range c.Tests {
				one, _ := json.Marshal([]any{map[string]any{"id": c.ID, "version": c.Version, "tests": []json.RawMessage{tst}}})
				f.Add(one)
			}
		}
	}
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"Controls":[]}`))
	f.Add([]byte(`{"Controls":[{"id":"5","version":"cis-1.12","tests":[{"section":"5.2","results":[{"test_number":"5.2.2","status":"WARN","test_desc":"Minimize (Manual)","type":""}]}]}]}`))
	f.Add([]byte(`[{"id":"1","tests":[{"results":[{"test_number":"1","status":" fail ","type":"MANUAL"}]}]}]`))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := Parse(in, "f.json")
		if err != nil {
			if got != nil {
				t.Fatalf("findings returned together with an error: %v", err)
			}
			return
		}
		for _, fd := range got {
			if fd.Scanner != "kube-bench" || fd.ResourceID != "cluster" {
				t.Fatalf("bad finding: %+v", fd)
			}
			if fd.Status != strings.TrimSpace(fd.Status) {
				t.Fatalf("status keeps spaces: %q", fd.Status)
			}
			if fd.IsManualWarn() && fd.Status != "WARN" {
				t.Fatalf("manual warn with status %q", fd.Status)
			}
		}
		again, err := Parse(in, "f.json")
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatal("parse is not deterministic")
		}
	})
}
