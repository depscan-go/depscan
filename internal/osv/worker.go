package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

func fetchDetails(ctx context.Context, client *http.Client, ids []string, maxWorkers int, baseURL string) ([]*vulnDetail, error) {
	results := make([]*vulnDetail, len(ids))
	errors := make([]error, len(ids))
	sem := make(chan struct{}, maxWorkers)

	var wg sync.WaitGroup

	for i, id := range ids {
		wg.Add(1)
		go func(idx int, vulnID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			detail, err := fetchOne(ctx, client, vulnID, baseURL)
			if err != nil {
				errors[idx] = err
				return
			}
			results[idx] = detail
		}(i, id)
	}

	wg.Wait()

	var combined []*vulnDetail
	for i, r := range results {
		if errors[i] != nil {
			fmt.Printf("[warn] failed to fetch vuln %s: %v\n", ids[i], errors[i])
			continue
		}
		if r != nil {
			combined = append(combined, r)
		}
	}

	return combined, nil
}

func fetchOne(ctx context.Context, client *http.Client, id string, baseURL string) (*vulnDetail, error) {
	url := baseURL + "/v1/vulns/" + id

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("vuln %s not found", id)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var detail vulnDetail
	if err := json.Unmarshal(data, &detail); err != nil {
		return nil, fmt.Errorf("decoding vuln detail: %w", err)
	}

	return &detail, nil
}