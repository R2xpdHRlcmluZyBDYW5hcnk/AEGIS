package console

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"testing"
)

func compareContract(t *testing.T, path string, actual, expected any) {
	t.Helper()
	switch want := expected.(type) {
	case map[string]any:
		got, ok := actual.(map[string]any)
		if !ok {
			t.Errorf("%s: got %T want object", path, actual)
			return
		}
		for key, value := range want {
			v, present := got[key]
			if !present {
				t.Errorf("%s.%s missing", path, key)
				continue
			}
			compareContract(t, path+"."+key, v, value)
		}
	case []any:
		got, ok := actual.([]any)
		if !ok {
			t.Errorf("%s: got %T want array", path, actual)
			return
		}
		if len(got) != len(want) {
			t.Errorf("%s: length got %d want %d", path, len(got), len(want))
			return
		}
		for i, v := range want {
			compareContract(t, fmt.Sprintf("%s[%d]", path, i), got[i], v)
		}
	default:
		if !reflect.DeepEqual(actual, expected) {
			t.Errorf("%s: got %#v want %#v", path, actual, expected)
		}
	}
}
func TestPythonQueryContracts(t *testing.T) {
	s, ctx := testStore(t)
	var fixtures []struct{ Raw string }
	data, _ := os.ReadFile("testdata/events.json")
	if err := decode(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	records := []*Prepared{}
	for _, fixture := range fixtures {
		p, err := ParseEvent([]byte(fixture.Raw))
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, p)
	}
	if err := s.insert(ctx, records, Cursor{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/queries.json")
	if err != nil {
		t.Fatal(err)
	}
	var reference Object
	if err = decode(data, &reference); err != nil {
		t.Fatal(err)
	}
	low, high := number(reference["low"]), number(reference["high"])
	g, err := s.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	total, events, err := search(ctx, g, low, high, nil, nil, 500, 0, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	security, err := securitySummary(ctx, g, low, high, nil, nil, true, "all", 5)
	if err != nil {
		t.Fatal(err)
	}
	network, err := networkSummary(ctx, g, low, high, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	grouped, err := incidents(ctx, g, url.Values{}, low, high, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	for name, actual := range map[string]any{"search": Object{"total": total, "events": events}, "security": security, "network": network, "incidents": grouped} {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(actual)
			var normalized any
			json.Unmarshal(data, &normalized)
			expected, _ := json.Marshal(reference[name])
			var want any
			json.Unmarshal(expected, &want)
			compareContract(t, name, normalized, want)
		})
	}
}

func TestPythonSearchCompatibility(t *testing.T) {
	s, ctx := testStore(t)
	var fixtures []struct{ Raw string }
	data, _ := os.ReadFile("testdata/events.json")
	if err := decode(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	records := []*Prepared{}
	for _, fixture := range fixtures {
		r, err := ParseEvent([]byte(fixture.Raw))
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	if err := s.insert(ctx, records, Cursor{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/hunt.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Query string
		ICase bool
		Total int64
	}
	if err = decode(data, &cases); err != nil {
		t.Fatal(err)
	}
	failures := 0
	for _, test := range cases {
		node, err := ParseHunt(test.Query)
		if err != nil {
			t.Errorf("parse %s: %v", test.Query, err)
			failures++
			continue
		}
		sql, args, err := compileHunt(node, test.ICase)
		if err != nil {
			t.Errorf("compile %s: %v", test.Query, err)
			failures++
			continue
		}
		var total int64
		if err = s.Readers.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE "+sql, args...).Scan(&total); err != nil {
			t.Errorf("query %s: %v", test.Query, err)
			failures++
		} else if total != test.Total {
			t.Errorf("%s icase=%v got %d want %d", test.Query, test.ICase, total, test.Total)
			failures++
		}
		if failures >= 30 {
			t.Fatal("too many search compatibility failures")
		}
	}
}

func TestPythonEventCompatibility(t *testing.T) {
	data, err := os.ReadFile("testdata/events.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name, Raw       string
		Record, Columns Object
	}
	if err = decode(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	canonical := func(value any) any {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var out any
		if err = json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			prepared, err := ParseEvent([]byte(fixture.Raw))
			if err != nil || prepared == nil {
				t.Fatalf("parse: %v", err)
			}
			for key, expected := range fixture.Record {
				actual, ok := prepared.Record[key]
				if !ok || !reflect.DeepEqual(canonical(actual), canonical(expected)) {
					t.Errorf("record.%s got %#v want %#v", key, actual, expected)
				}
			}
			for i, pair := range schema.Columns {
				column := *pair[0]
				if column == "raw" {
					continue
				}
				actual, expected := prepared.Values[i], fixture.Columns[column]
				if !reflect.DeepEqual(canonical(actual), canonical(expected)) {
					t.Errorf("column.%s got %#v want %#v", column, actual, expected)
				}
			}
		})
	}
}
