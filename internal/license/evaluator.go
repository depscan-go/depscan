package license

import "strings"

func Unknown(expr string) bool {
	e := strings.TrimSpace(expr)
	return e == "" || strings.EqualFold(e, "NOASSERTION") || strings.EqualFold(e, "non-standard")
}

func Check(expr string, deny map[string]bool, allowUnknown bool) (ok bool, reason string) {
	if Unknown(expr) {
		if allowUnknown {
			return true, ""
		}
		return false, "license is unknown and policy blocks unknown licenses"
	}

	e := strings.NewReplacer("(", " ", ")", " ").Replace(expr)
	tokens := strings.Fields(e)

	var ids []string
	hasOr, hasAnd := false, false
	for i := 0; i < len(tokens); i++ {
		switch strings.ToUpper(tokens[i]) {
		case "OR":
			hasOr = true
		case "AND":
			hasAnd = true
		case "WITH":
			i++ // skip the exception, e.g. "GPL-2.0-only WITH Classpath-exception-2.0"
		default:
			ids = append(ids, normalizeID(tokens[i]))
		}
	}

	var denied []string
	for _, id := range ids {
		if deny[strings.ToLower(id)] {
			denied = append(denied, id)
		}
	}

	if hasOr && !hasAnd {
		if len(denied) < len(ids) {
			return true, ""
		}
		return false, "every license option is denied by policy: " + strings.Join(denied, ", ")
	}

	if len(denied) > 0 {
		return false, "license denied by policy: " + strings.Join(denied, ", ")
	}
	return true, ""
}

// DenySet builds the lowercase lookup map Check expects.
func DenySet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[strings.ToLower(normalizeID(strings.TrimSpace(id)))] = true
	}
	return m
}

func normalizeID(id string) string {
	if strings.HasSuffix(id, "+") {
		return strings.TrimSuffix(id, "+") + "-or-later"
	}
	return id
}
