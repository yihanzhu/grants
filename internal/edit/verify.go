package edit

import "reflect"

// equalDecoded is reflect.DeepEqual for decoded JSON and TOML values, except that
// NaN equals NaN (TOML allows nan, and DeepEqual would reject an unchanged document).
func equalDecoded(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !equalDecoded(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equalDecoded(x[i], y[i]) {
				return false
			}
		}
		return true
	case []map[string]any:
		y, ok := b.([]map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equalDecoded(x[i], y[i]) {
				return false
			}
		}
		return true
	case float64:
		y, ok := b.(float64)
		return ok && (x == y || (x != x && y != y))
	}
	return reflect.DeepEqual(a, b)
}
