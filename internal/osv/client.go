package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/depscan-go/depscan/internal/model"
)

const (
	batchSize = 100
)

func NewWithBaseURL(baseURL string) *Client {
	c := New()
	c.baseURL = baseURL
	return c
}

type Client struct {
	http    *http.Client
	workers int
	baseURL string
}

func New() *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		workers: 8,
		baseURL: "https://api.osv.dev",
	}
}

type batchQuery struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type vulnDetail struct {
	ID       string   `json:"id"`
	Modified string   `json:"modified"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func (c *Client) QueryBatch(ctx context.Context, deps []model.Dependency) ([]model.Finding, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	depVulns, err := c.batchQuery(ctx, deps)
	if err != nil {
		return nil, fmt.Errorf("batch query: %w", err)
	}

	seen := make(map[string]bool)
	var uniqueIDs []string
	for _, ids := range depVulns {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				uniqueIDs = append(uniqueIDs, id)
			}
		}
	}

	if len(uniqueIDs) == 0 {
		return nil, nil
	}

	details, err := fetchDetails(ctx, c.http, uniqueIDs, c.workers, c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("fetching vuln details: %w", err)
	}

	detailMap := make(map[string]*vulnDetail, len(details))
	for _, d := range details {
		d := d
		detailMap[d.ID] = d
	}

	var findings []model.Finding
	for i, dep := range deps {
		for _, vulnID := range depVulns[i] {
			detail, ok := detailMap[vulnID]
			if !ok {
				continue
			}
			findings = append(findings, model.Finding{
				Dep:          dep,
				VulnID:       detail.ID,
				Aliases:      detail.Aliases,
				Severity:     extractSeverity(detail),
				Summary:      detail.Summary,
				FixedVersion: extractFixedVersion(detail, dep),
				Modified:     detail.Modified,
			})
		}
	}

	return findings, nil
}

func (c *Client) batchQuery(ctx context.Context, deps []model.Dependency) ([][]string, error) {
	result := make([][]string, len(deps))

	for start := 0; start < len(deps); start += batchSize {
		end := start + batchSize
		if end > len(deps) {
			end = len(deps)
		}
		chunk := deps[start:end]

		queries := make([]osvQuery, len(chunk))
		for i, dep := range chunk {
			queries[i] = osvQuery{
				Package: osvPackage{
					Name:      dep.Name,
					Ecosystem: dep.Ecosystem,
				},
				Version: dep.Version,
			}
		}

		body, err := json.Marshal(batchQuery{Queries: queries})
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/querybatch", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("POST querybatch: %w", err)
		}

		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close() // read-only body: a close error changes nothing
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OSV querybatch returned %d", resp.StatusCode)
		}

		var br batchResponse
		if err := json.Unmarshal(data, &br); err != nil {
			return nil, fmt.Errorf("decoding batch response: %w", err)
		}

		if len(br.Results) != len(chunk) {
			return nil, fmt.Errorf("OSV returned %d results for %d queries", len(br.Results), len(chunk))
		}

		for i, res := range br.Results {
			var ids []string
			for _, v := range res.Vulns {
				ids = append(ids, v.ID)
			}
			result[start+i] = ids
		}
	}

	return result, nil
}

func extractSeverity(d *vulnDetail) string {
	if d.DatabaseSpecific.Severity != "" {
		return d.DatabaseSpecific.Severity
	}
	return "UNKNOWN"
}

// extractFixedVersion returns the fixed version for THIS dependency only.
// One advisory can list several affected packages (for example x/crypto and
// Helm), so we must match on package name and ecosystem. Returns "" when no
// fix is published, rather than guessing.
func extractFixedVersion(d *vulnDetail, dep model.Dependency) string {
	for _, aff := range d.Affected {
		if aff.Package.Name != dep.Name || aff.Package.Ecosystem != dep.Ecosystem {
			continue
		}
		for _, r := range aff.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}
