package main

import (
	"context"
	"log"
	"time"

	"github.com/depscan-go/depscan/internal/api"
	"github.com/depscan-go/depscan/internal/github"
	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/store"
)

// saveOutcome saves a finished pull request scan and, when a is not nil,
// anchors its report and saves that too. It returns the scan ID the status
// and comment may link to: "" when the scan wasn't saved. o.Anchor.ReportSaved
// says whether the report can be downloaded. A comment never links to
// something that wasn't saved.
func saveOutcome(h *api.Handler, a anchorer, p *policy.Policy, o *github.Outcome, label string) string {
	rec, err := h.Record(context.Background(), store.PR, label, o.Result)
	scanID := ""
	if err == nil {
		scanID = rec.ID
	}
	if a == nil {
		return scanID
	}
	// Anchor before reporting, so the comment can carry the transaction. A
	// devnet anchor takes a few seconds, well inside the time the app stays up
	// after the webhook request.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	data, info, err := anchorScan(ctx, a, p, *o)
	cancel()
	if err != nil {
		log.Printf("webhook: %s: anchoring %s: %v", label, info.Digest, err)
	} else {
		log.Printf("webhook: %s: anchored %s in %s", label, info.Digest, info.Anchor.TxID)
	}
	if data == nil {
		return scanID
	}
	o.Anchor = anchorNote(info)
	if scanID != "" && o.Anchor != nil {
		o.Anchor.ReportSaved = h.AttachReport(context.Background(), rec, data, info) == nil
	}
	return scanID
}
