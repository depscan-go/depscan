package license

import "testing"

func TestCheck(t *testing.T) {
	deny := DenySet([]string{"GPL-3.0-only", "AGPL-3.0-only", "GPL-2.0-or-later"})

	tests := []struct {
		name         string
		expr         string
		allowUnknown bool
		wantOK       bool
	}{
		{"permissive single", "MIT", false, true},
		{"denied single", "GPL-3.0-only", false, false},
		{"case insensitive", "gpl-3.0-ONLY", false, false},
		{"OR with an allowed option", "MIT OR GPL-3.0-only", false, true},
		{"OR where every option is denied", "GPL-3.0-only OR AGPL-3.0-only", false, false},
		{"AND with a denied part", "MIT AND GPL-3.0-only", false, false},
		{"AND all allowed", "MIT AND Apache-2.0", false, true},
		{"parentheses", "(MIT OR GPL-3.0-only)", false, true},
		{"mixed AND/OR is conservative", "MIT OR (Apache-2.0 AND GPL-3.0-only)", false, false},
		{"WITH exception is skipped", "Apache-2.0 WITH LLVM-exception", false, true},
		{"deprecated plus form", "GPL-2.0+", false, false},
		{"unknown allowed", "", true, true},
		{"unknown blocked", "", false, false},
		{"NOASSERTION blocked", "NOASSERTION", false, false},
		{"non-standard blocked", "non-standard", false, false},
		{"non-standard allowed", "non-standard", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := Check(tt.expr, deny, tt.allowUnknown)
			if ok != tt.wantOK {
				t.Errorf("Check(%q) = %v (%q), want %v", tt.expr, ok, reason, tt.wantOK)
			}
			if !ok && reason == "" {
				t.Errorf("Check(%q) denied without a reason", tt.expr)
			}
		})
	}
}
