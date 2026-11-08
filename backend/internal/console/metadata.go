package console

import (
	"strings"
)

func matchMetadata(raw any, field, value string, icase bool) bool {
	data, ok := raw.([]byte)
	if !ok || len(data) == 0 {
		return false
	}
	decoded, err := decompress(data)
	if err != nil {
		return false
	}
	var envelope Object
	if decode(decoded, &envelope) != nil {
		return false
	}
	event, err := nativeEvent(envelope)
	if err != nil || event == nil {
		return false
	}
	record := Object{}
	attackMetadata(record, object(object(event["alert"])["metadata"]))
	items := array(record[field])
	if value == "*" {
		return len(items) > 0
	}
	for _, raw := range items {
		item, query := text(raw), value
		if icase || strings.HasSuffix(field, "_id") {
			item, query = strings.ToLower(item), strings.ToLower(query)
		}
		if strings.ContainsAny(query, "*?") {
			if huntSubstrings[field] {
				query = "*" + query + "*"
			}
			if glob(query, item) {
				return true
			}
		} else if huntSubstrings[field] && strings.Contains(item, query) {
			return true
		} else if !huntSubstrings[field] && item == query {
			return true
		}
	}
	return false
}
