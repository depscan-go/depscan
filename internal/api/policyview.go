package api

import "net/http"

// policyView is the policy the server loaded at startup, as the dashboard
// reads it to explain each verdict ("HIGH is in block_severities"). It is
// read-only: change policy.yaml and restart the server to change the rules.
type policyView struct {
	Digest               string          `json:"digest"` // same value as policy.Policy.Digest
	BlockSeverities      []string        `json:"block_severities"`
	WarnSeverities       []string        `json:"warn_severities"`
	BlockUnknownSeverity bool            `json:"block_unknown_severity"`
	CheckTransitive      bool            `json:"check_transitive"`
	DeniedLicenses       []string        `json:"denied_licenses"`
	BlockUnknownLicense  bool            `json:"block_unknown_license"`
	SkipLicenseCheck     bool            `json:"skip_license_check"`
	Exceptions           []exceptionView `json:"exceptions"`
	FailFast             bool            `json:"fail_fast"`
	MaxViolations        int             `json:"max_violations"`
}

type exceptionView struct {
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	Expires string `json:"expires,omitempty"` // YYYY-MM-DD, valid through that whole day
}

// PolicyView handles GET /policy.
func (h *Handler) PolicyView(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil || h.engine.Policy == nil {
		writeError(w, http.StatusNotFound, "no policy loaded")
		return
	}
	p := h.engine.Policy
	digest, err := p.Digest()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	v := policyView{
		Digest:               digest,
		BlockSeverities:      orEmpty(p.BlockSeverities),
		WarnSeverities:       orEmpty(p.WarnSeverities),
		BlockUnknownSeverity: p.BlockUnknown,
		CheckTransitive:      p.CheckTransitive,
		DeniedLicenses:       orEmpty(p.DeniedLicenses),
		BlockUnknownLicense:  p.BlockUnknownLicense,
		SkipLicenseCheck:     p.SkipLicenseCheck,
		Exceptions:           make([]exceptionView, 0, len(p.Exceptions)),
		FailFast:             p.FailFast,
		MaxViolations:        p.MaxViolations,
	}
	for _, e := range p.Exceptions {
		v.Exceptions = append(v.Exceptions, exceptionView{ID: e.ID, Reason: e.Reason, Expires: e.Expires})
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, v)
}

// orEmpty keeps empty lists as [] in JSON instead of null.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
