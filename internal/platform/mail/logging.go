package mail

import (
	"context"
	"errors"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
)

// productionEnvironment is the service environment the logging mailer refuses
// to run in.
const productionEnvironment = "production"

// ErrProductionEnvironment reports an attempt to use the logging mailer in
// production, where mail must actually be delivered.
var ErrProductionEnvironment = errors.New("mail: the logging mailer cannot run in production")

// Logging is the development mailer: instead of delivering, it writes one log
// line per message with the recipient's hash, the template and the action
// link, so a developer can follow a verification or reset link from the log.
//
// The link contains the one-time token, which is why this mailer refuses to be
// built in production: there the link must go to the recipient, not to the log.
type Logging struct {
	log     logger.Logger
	baseURL string
}

// NewLogging returns a Logging mailer building links under baseURL. It fails
// in production, so a deployment that forgot to configure a real mailer does
// not silently print tokens to its logs. log may be nil.
func NewLogging(log logger.Logger, environment, baseURL string) (*Logging, error) {
	if environment == productionEnvironment {
		return nil, errorz.Wrap(ErrProductionEnvironment).
			WithCode(errorz.CodePreconditionFailed).
			WithMessage(ErrProductionEnvironment.Error())
	}
	if baseURL == "" {
		return nil, errorz.PreconditionFailed().WithMessage("mail: the logging mailer needs a base URL")
	}
	if log == nil {
		log = logger.NewNoOp()
	}
	return &Logging{log: log, baseURL: baseURL}, nil
}

// Send logs the message instead of delivering it.
func (l *Logging) Send(ctx context.Context, m *Message) error {
	l.log.InfoWithContext(ctx, "mail not sent: development logging mailer",
		logger.F("recipient_hash", m.RecipientHash()),
		logger.F("template", m.Template),
		logger.F("link", m.Link(l.baseURL)))
	return nil
}
