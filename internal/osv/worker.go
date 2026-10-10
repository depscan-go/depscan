package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/depscan-go/depscan/internal/httpx"
)

func fetchDetails(ctx context.Context, client *http.Client, ids []string, maxWorkers int, baseURL string) ([]*vulnDetail, error) {
	results := make([]*vulnDetail, len(ids))
	errs := make([]error, len(ids))
	sem := make(chan struct{}, maxWorkers)

	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(idx int, vulnID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx], errs[idx] = fetchOne(ctx, client, vulnID, baseURL)
		}(i, id)
	}
	wg.Wait()

	var combined []*vulnDetail
	for i, r := range results {
		if errs[i] != nil {
			return nil, fmt.Errorf("fetching advisory %s: %w", ids[i], errs[i])
		}
		if r != nil {
			combined = append(combined, r)
		}
	}
	return combined, nil
}

func fetchOne(ctx context.Context, client *http.Client, id string, baseURL string) (*vulnDetail, error) {
	u := baseURL + "/v1/vulns/" + url.PathEscape(id)

	status, data, err := httpx.Do(ctx, client, httpx.Default, 10<<20, func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	})
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	if status == http.StatusNotFound {
		fmt.Printf("[warn] advisory %s not found on OSV, skipping\n", id)
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", u, status)
	}

	var detail vulnDetail
	if err := json.Unmarshal(data, &detail); err != nil {
		return nil, fmt.Errorf("decoding advisory %s: %w", id, err)
	}
	return &detail, nil
}
