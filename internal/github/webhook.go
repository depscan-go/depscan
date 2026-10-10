package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

const maxPayload = 1 << 20

var (
	ErrBadSignature = errors.New("invalid webhook signature")
)

type Job struct {
	DeliveryID string
	Repo       string
	PR         int
	HeadRepo   string
	HeadSHA    string
	Action     string
}

func VerifySignature(secret, body []byte, header string) error {
	hexSig, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return ErrBadSignature
	}
	sig, err := hex.DecodeString(hexSig)
	if err != nil {
		return ErrBadSignature
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body) // hash.Hash.Write never returns an error
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return ErrBadSignature
	}
	return nil
}

var scanActions = map[string]bool{
	"opened":           true,
	"synchronize":      true, // new commits pushed
	"reopened":         true,
	"ready_for_review": true,
}

type pullRequestEvent struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Head struct {
			SHA  string `json:"sha"`
			Repo *struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type WebhookHandler struct {
	secret  []byte
	enqueue func(Job) bool

	mu   sync.Mutex
	seen map[string]bool
	ring []string
}

func NewWebhookHandler(secret string, enqueue func(Job) bool) (*WebhookHandler, error) {
	if secret == "" {
		return nil, errors.New("webhook secret is required")
	}
	return &WebhookHandler{secret: []byte(secret), enqueue: enqueue, seen: map[string]bool{}}, nil
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPayload))
	if err != nil {
		reply(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}

	if err := VerifySignature(h.secret, body, r.Header.Get("X-Hub-Signature-256")); err != nil {
		reply(w, http.StatusUnauthorized, err.Error())
		return
	}

	switch event := r.Header.Get("X-GitHub-Event"); event {
	case "ping":
		reply(w, http.StatusOK, "pong")
		return
	case "pull_request":
	default:
		reply(w, http.StatusAccepted, "ignored event "+event)
		return
	}

	var ev pullRequestEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		reply(w, http.StatusBadRequest, "invalid pull_request payload")
		return
	}
	if !scanActions[ev.Action] {
		reply(w, http.StatusAccepted, "ignored action "+ev.Action)
		return
	}
	if ev.Repository.FullName == "" || ev.PullRequest.Head.SHA == "" || ev.PullRequest.Head.Repo == nil {
		reply(w, http.StatusUnprocessableEntity, "pull_request payload is missing the repository or head commit")
		return
	}

	job := Job{
		DeliveryID: r.Header.Get("X-GitHub-Delivery"),
		Repo:       ev.Repository.FullName,
		PR:         ev.Number,
		HeadRepo:   ev.PullRequest.Head.Repo.FullName,
		HeadSHA:    ev.PullRequest.Head.SHA,
		Action:     ev.Action,
	}

	if h.duplicate(job.DeliveryID) {
		reply(w, http.StatusOK, "duplicate delivery")
		return
	}
	if !h.enqueue(job) {
		h.forget(job.DeliveryID) // let GitHub's redelivery try again
		reply(w, http.StatusServiceUnavailable, "scan queue is full, redeliver later")
		return
	}
	log.Printf("webhook: queued %s#%d at %.7s (%s)", job.Repo, job.PR, job.HeadSHA, job.Action)
	reply(w, http.StatusAccepted, "queued")
}

const seenLimit = 1000

func (h *WebhookHandler) duplicate(id string) bool {
	if id == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen[id] {
		return true
	}
	h.seen[id] = true
	h.ring = append(h.ring, id)
	if len(h.ring) > seenLimit {
		delete(h.seen, h.ring[0])
		h.ring = h.ring[1:]
	}
	return false
}

func (h *WebhookHandler) forget(id string) {
	h.mu.Lock()
	delete(h.seen, id)
	h.mu.Unlock()
}

func reply(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"status": msg}); err != nil {
		log.Printf("webhook: writing response: %v", err)
	}
}
