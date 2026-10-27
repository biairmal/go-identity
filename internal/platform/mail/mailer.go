// Package mail carries the service's outgoing email: the Mailer port the
// worker delivers through, a development logging stub, and Queue, which puts a
// message on the outbox inside the caller's transaction. It holds no business
// logic: the caller chooses the template, the link path and the data, so this
// package can move into the service template unchanged.
package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"time"
)

// Topic is the outbox topic mail is queued under. The worker routes it to the
// Mailer.
const Topic = "mail.send"

// Message is one email. It travels through the outbox as JSON, so every field
// is explicitly tagged.
type Message struct {
	// To is the recipient address. It is never logged: logs carry
	// RecipientHash instead.
	To string `json:"to"`
	// Subject is the mail subject line.
	Subject string `json:"subject"`
	// Template names the body to render, without its extension.
	Template string `json:"template"`
	// LinkPath is the frontend path of the action link, e.g.
	// "/verify-email". Empty for mail without a link.
	LinkPath string `json:"link_path,omitempty"`
	// Token is the one-time token the link carries. It is the only secret
	// in the payload: the link is built from it at delivery time, the
	// dispatcher clears it once the mail is sent, and it is never stored
	// anywhere else in the clear.
	Token string `json:"token,omitempty"`
	// ExpiresAt is when Token stops working. Past it the dispatcher never
	// sends the mail and the cleanup job deletes it. Zero for mail without
	// a token, which then keeps the outbox's usual retry window.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	// Data holds the remaining template variables.
	Data map[string]string `json:"data,omitempty"`
}

// Link builds the action link under baseURL. The token goes in the URL
// fragment, so it never reaches server logs, proxies or Referer headers.
// It returns "" when the message has no link.
func (m *Message) Link(baseURL string) string {
	if m.LinkPath == "" {
		return ""
	}
	link := strings.TrimSuffix(baseURL, "/") + m.LinkPath
	if m.Token == "" {
		return link
	}
	return link + "#token=" + url.QueryEscape(m.Token)
}

// RecipientHash identifies the recipient in logs and metrics without
// revealing the address: the SHA-256 of the normalized address, hex encoded.
func (m *Message) RecipientHash() string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(m.To))))
	return hex.EncodeToString(sum[:])
}

// Mailer delivers one message. Implementations must tolerate duplicates: the
// outbox resends a message whose delivery was not recorded.
type Mailer interface {
	Send(ctx context.Context, m *Message) error
}
