package app

import (
	"context"
	"io"
	"mime/quotedprintable"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/biairmal/go-identity/internal/module/auth/templates"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/mail"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// smtpSession is what the test SMTP server received in one connection.
type smtpSession struct {
	from, to, data string
}

// startSMTP runs a minimal plain-text SMTP server on a local listener (EHLO,
// MAIL, RCPT, DATA, QUIT: what net/smtp needs without TLS or AUTH) and returns
// its port and the sessions it completes.
func startSMTP(t *testing.T) (port int, sessions <-chan smtpSession) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan smtpSession, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSMTP(conn, ch)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

func serveSMTP(conn net.Conn, sessions chan<- smtpSession) {
	defer func() { _ = conn.Close() }()
	tp := textproto.NewConn(conn)
	var got smtpSession
	reply := func(line string) { _ = tp.PrintfLine("%s", line) }
	reply("220 test ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			reply("250 test")
		case "MAIL":
			got.from = arg
			reply("250 ok")
		case "RCPT":
			got.to = arg
			reply("250 ok")
		case "DATA":
			reply("354 go on")
			b, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			got.data = string(b)
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			sessions <- got
			return
		default:
			reply("502 unknown")
		}
	}
}

// TestWorkerSendsMailOverSMTP drives a queued verification mail through the
// production worker's sender, the go-sdk mailer adapter and a local SMTP
// listener: the recipient gets the rendered template with its link, and the
// outbox row is marked sent.
func TestWorkerSendsMailOverSMTP(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	port, sessions := startSMTP(t)

	cfg := Config{Service: ServiceConfig{Environment: EnvProduction}, Modules: defaultModules()}
	cfg.Modules.Auth.FrontendURLs = []string{"https://app.example.com"}
	cfg.Mail.From = "Identity <no-reply@example.com>"
	cfg.Mail.Host = "127.0.0.1"
	cfg.Mail.Port = port
	cfg.Mail.TLS = "none"
	topics, err := senders(&cfg, nil, db)
	if err != nil {
		t.Fatalf("senders() in production with mail configured = %v", err)
	}

	msg := templates.VerifyEmailMessage("bia@example.com", "raw-token", time.Now().Add(time.Hour),
		map[string]string{"DisplayName": "Bia"})
	if err := mail.Queue(ctx, database.NewOutbox(db), msg); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	if n, err := database.NewDispatcher(db, topics, nil).DispatchOnce(ctx); err != nil || n != 1 {
		t.Fatalf("DispatchOnce = %d, %v; want 1 row", n, err)
	}

	var got smtpSession
	select {
	case got = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("the SMTP server received no mail")
	}
	if got.from != "FROM:<no-reply@example.com>" || got.to != "TO:<bia@example.com>" {
		t.Errorf("envelope = %q / %q, want the configured sender and the recipient", got.from, got.to)
	}
	header, rawBody, _ := strings.Cut(got.data, "\n\n") // ReadDotBytes turns CRLF into LF
	if !strings.Contains(header, "Subject: Confirm your email address") {
		t.Errorf("headers lack the template's subject:\n%s", header)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(rawBody)))
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	for _, want := range []string{"Welcome Bia.", "https://app.example.com/verify-email#token=raw-token"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}

	var sent int
	if err := db.Leader().QueryRowContext(ctx,
		`SELECT count(*) FROM outbox WHERE topic = $1 AND sent_at IS NOT NULL`, mail.Topic).Scan(&sent); err != nil {
		t.Fatalf("count sent rows: %v", err)
	}
	if sent != 1 {
		t.Errorf("%d mail rows marked sent, want 1", sent)
	}
}
