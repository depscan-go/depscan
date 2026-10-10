package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Policy says how often and how patiently to retry.
type Policy struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
}

var Default = Policy{Attempts: 3, BaseDelay: 500 * time.Millisecond, MaxDelay: 8 * time.Second}

func Do(ctx context.Context, c *http.Client, p Policy, limit int64, newReq func(context.Context) (*http.Request, error)) (int, []byte, error) {
	if p.Attempts < 1 {
		p.Attempts = 1
	}
	for attempt := 1; ; attempt++ {
		req, err := newReq(ctx)
		if err != nil {
			return 0, nil, err
		}

		var wait time.Duration
		resp, err := c.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit))
			_ = resp.Body.Close() // read-only body: a close error changes nothing
			switch {
			case readErr != nil:
				err = fmt.Errorf("reading response from %s: %w", req.URL.Host, readErr)
			case !retryable(resp) || attempt >= p.Attempts:
				return resp.StatusCode, body, nil
			default:
				err = fmt.Errorf("%s returned %d", req.URL.Host, resp.StatusCode)
				wait = retryAfter(resp)
			}
		}
		if ctx.Err() != nil {
			return 0, nil, ctx.Err() // cancelled or timed out: stop now
		}
		if attempt >= p.Attempts {
			return 0, nil, fmt.Errorf("after %d attempts: %w", attempt, err)
		}

		if wait == 0 {
			wait = p.BaseDelay << (attempt - 1)
		}
		if wait > p.MaxDelay {
			wait = p.MaxDelay
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func retryable(resp *http.Response) bool {
	switch {
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return true
	case resp.StatusCode == http.StatusForbidden:
		return resp.Header.Get("Retry-After") != ""
	}
	return false
}

// retryAfter reads a Retry-After header given in seconds; 0 if absent.
func retryAfter(resp *http.Response) time.Duration {
	s, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || s < 0 {
		return 0
	}
	return time.Duration(s) * time.Second
}
