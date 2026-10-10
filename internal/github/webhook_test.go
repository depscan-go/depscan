package github_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/depscan-go/depscan/internal/github"
)

const secret = "test-secret"

func sign(body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

const prOpened = `{
  "action": "opened",
  "number": 42,
  "pull_request": {"head": {"sha": "0123456789abcdef0123456789abcdef01234567", "repo": {"full_name": "fork-owner/depscan"}}},
  "repository": {"full_name": "depscan-go/depscan"}
}`

type recorder struct {
	jobs []github.Job
	full bool
}

func (r *recorder) enqueue(j github.Job) bool {
	if r.full {
		return false
	}
	r.jobs = append(r.jobs, j)
	return true
}

func newHandler(t *testing.T, rec *recorder) *github.WebhookHandler {
	t.Helper()
	h, err := github.NewWebhookHandler(secret, rec.enqueue)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func deliver(h http.Handler, event, delivery, body, signature string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", delivery)
	if signature != "" {
		req.Header.Set("X-Hub-Signature-256", signature)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestVerifySignature(t *testing.T) {
	body := []byte(`{"a":1}`)
	good := sign(string(body))

	if err := github.VerifySignature([]byte(secret), body, good); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
	bad := map[string]string{
		"missing":     "",
		"no prefix":   strings.TrimPrefix(good, "sha256="),
		"sha1 prefix": "sha1=" + strings.TrimPrefix(good, "sha256="),
		"not hex":     "sha256=zzzz",
		"wrong secret": func() string {
			m := hmac.New(sha256.New, []byte("other"))
			m.Write(body)
			return "sha256=" + hex.EncodeToString(m.Sum(nil))
		}(),
		"body changed": sign(`{"a":2}`),
	}
	for name, sig := range bad {
		if err := github.VerifySignature([]byte(secret), body, sig); !errors.Is(err, github.ErrBadSignature) {
			t.Errorf("%s: got %v, want ErrBadSignature", name, err)
		}
	}
}

func TestNewWebhookHandler_RequiresSecret(t *testing.T) {
	if _, err := github.NewWebhookHandler("", func(github.Job) bool { return true }); err == nil {
		t.Fatal("an empty secret must be refused")
	}
}

func TestWebhook_QueuesPullRequest(t *testing.T) {
	rec := &recorder{}
	w := deliver(newHandler(t, rec), "pull_request", "d-1", prOpened, sign(prOpened))

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", w.Code, w.Body)
	}
	if len(rec.jobs) != 1 {
		t.Fatalf("queued %d jobs, want 1", len(rec.jobs))
	}
	want := github.Job{
		DeliveryID: "d-1",
		Repo:       "depscan-go/depscan",
		PR:         42,
		HeadRepo:   "fork-owner/depscan",
		HeadSHA:    "0123456789abcdef0123456789abcdef01234567",
		Action:     "opened",
	}
	if rec.jobs[0] != want {
		t.Errorf("job = %+v, want %+v", rec.jobs[0], want)
	}
}

func TestWebhook_RejectsBadSignatureBeforeParsing(t *testing.T) {
	rec := &recorder{}
	h := newHandler(t, rec)

	for name, sig := range map[string]string{"missing": "", "forged": sign(prOpened + " ")} {
		w := deliver(h, "pull_request", "d-"+name, prOpened, sig)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, w.Code)
		}
	}
	if len(rec.jobs) != 0 {
		t.Errorf("unsigned requests queued %d jobs", len(rec.jobs))
	}
}

func TestWebhook_Ping(t *testing.T) {
	body := `{"zen":"Keep it logically awesome."}`
	if w := deliver(newHandler(t, &recorder{}), "ping", "d-1", body, sign(body)); w.Code != http.StatusOK {
		t.Errorf("ping status = %d, want 200", w.Code)
	}
}

func TestWebhook_IgnoresOtherEventsAndActions(t *testing.T) {
	rec := &recorder{}
	h := newHandler(t, rec)

	push := `{"ref":"refs/heads/main"}`
	if w := deliver(h, "push", "d-1", push, sign(push)); w.Code != http.StatusAccepted {
		t.Errorf("push status = %d, want 202", w.Code)
	}
	closed := strings.Replace(prOpened, `"opened"`, `"closed"`, 1)
	if w := deliver(h, "pull_request", "d-2", closed, sign(closed)); w.Code != http.StatusAccepted {
		t.Errorf("closed status = %d, want 202", w.Code)
	}
	if len(rec.jobs) != 0 {
		t.Errorf("ignored events queued %d jobs", len(rec.jobs))
	}
}

func TestWebhook_DuplicateDeliveryIsQueuedOnce(t *testing.T) {
	rec := &recorder{}
	h := newHandler(t, rec)
	deliver(h, "pull_request", "same-id", prOpened, sign(prOpened))
	w := deliver(h, "pull_request", "same-id", prOpened, sign(prOpened))

	if w.Code != http.StatusOK || len(rec.jobs) != 1 {
		t.Errorf("redelivery: status %d, %d jobs; want 200 and 1 job", w.Code, len(rec.jobs))
	}
}

func TestWebhook_FullQueueAsksForRedelivery(t *testing.T) {
	rec := &recorder{full: true}
	h := newHandler(t, rec)
	if w := deliver(h, "pull_request", "d-1", prOpened, sign(prOpened)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	// Once there is room, the same delivery must be accepted, not seen as a duplicate.
	rec.full = false
	if w := deliver(h, "pull_request", "d-1", prOpened, sign(prOpened)); w.Code != http.StatusAccepted {
		t.Errorf("redelivery after a full queue: status = %d, want 202", w.Code)
	}
}

func TestWebhook_BadPayloads(t *testing.T) {
	h := newHandler(t, &recorder{})
	cases := map[string]struct {
		body string
		want int
	}{
		"not JSON":       {`{"action":`, http.StatusBadRequest},
		"no head commit": {`{"action":"opened","number":1,"repository":{"full_name":"a/b"},"pull_request":{"head":{"repo":{"full_name":"a/b"}}}}`, http.StatusUnprocessableEntity},
		"deleted fork":   {`{"action":"opened","number":1,"repository":{"full_name":"a/b"},"pull_request":{"head":{"sha":"x","repo":null}}}`, http.StatusUnprocessableEntity},
		"too large":      {`{"x":"` + strings.Repeat("a", 1<<20) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for name, c := range cases {
		if w := deliver(h, "pull_request", "d-"+name, c.body, sign(c.body)); w.Code != c.want {
			t.Errorf("%s: status = %d, want %d", name, w.Code, c.want)
		}
	}
}
