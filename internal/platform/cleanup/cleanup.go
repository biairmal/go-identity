// Package cleanup deletes rows that are past their retention window:
// expired OAuth states, spent one-time tokens, dead refresh tokens and sent
// outbox rows. It runs in the worker, in bounded batches with
// FOR UPDATE SKIP LOCKED, so several worker pods are safe and one pass never
// locks a table for long.
package cleanup

import (
	"context"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/database"
)

// Defaults for the cleanup job.
const (
	// DefaultBatchSize bounds one delete statement, so a pass never holds
	// locks on a large number of rows.
	DefaultBatchSize = 1000
	// DefaultInterval is how often the job runs; the windows are days, so
	// once a day is enough.
	DefaultInterval = 24 * time.Hour
	// retention is how long a dead row is kept for investigation after it
	// expires or is revoked.
	retention = 30 * 24 * time.Hour
	// sentRetention is how long a delivered outbox row is kept.
	sentRetention = 7 * 24 * time.Hour
)

// Job deletes expired rows. One instance serves every table.
type Job struct {
	db    *sqlkit.DB
	clock clock.Clock
	log   logger.Logger
	batch int
}

// New returns a Job over db. clk and log may be nil.
func New(db *sqlkit.DB, clk clock.Clock, log logger.Logger) *Job {
	if clk == nil {
		clk = clock.System{}
	}
	if log == nil {
		log = logger.NewNoOp()
	}
	return &Job{db: db, clock: clk, log: log, batch: DefaultBatchSize}
}

// task is one table's retention rule.
type task struct {
	name string
	// sql deletes up to $1 rows that are past their window, claiming them
	// with FOR UPDATE SKIP LOCKED so a second worker skips locked rows
	// instead of waiting.
	sql string
	// args beyond the batch size.
	args func(now time.Time) []any
}

// tasks are the retention rules, in the order they run.
func (j *Job) tasks() []task {
	return []task{
		{
			name: "oauth_states",
			// A sign-in that was never completed: the state is useless
			// the moment it expires, so there is no retention window.
			sql: `DELETE FROM oauth_states WHERE state_hash IN (
			          SELECT state_hash FROM oauth_states WHERE expires_at < $2
			          ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)`,
			args: func(now time.Time) []any { return []any{now} },
		},
		{
			name: "one_time_tokens",
			// Kept for a while after use or expiry, so a support
			// question about a verification link can be answered.
			sql: `DELETE FROM one_time_tokens WHERE id IN (
			          SELECT id FROM one_time_tokens
			          WHERE (used_at IS NOT NULL AND used_at < $2) OR expires_at < $2
			          ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)`,
			args: func(now time.Time) []any { return []any{now.Add(-retention)} },
		},
		{
			name: "refresh_tokens",
			// Revoked or long expired. A revoked family is kept for the
			// retention window, because it is evidence of a reuse.
			sql: `DELETE FROM refresh_tokens WHERE id IN (
			          SELECT id FROM refresh_tokens
			          WHERE (revoked_at IS NOT NULL AND revoked_at < $2)
			             OR absolute_expires_at < $2
			          ORDER BY absolute_expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)`,
			args: func(now time.Time) []any { return []any{now.Add(-retention)} },
		},
		{
			name: "outbox_sent",
			sql: `DELETE FROM outbox WHERE id IN (
			          SELECT id FROM outbox WHERE sent_at IS NOT NULL AND sent_at < $2
			          ORDER BY sent_at LIMIT $1 FOR UPDATE SKIP LOCKED)`,
			args: func(now time.Time) []any { return []any{now.Add(-sentRetention)} },
		},
		{
			name: "outbox_unsendable",
			// A mail row whose one-time token has expired can never be
			// useful: the link in it would be rejected. Dropping it
			// stops the dispatcher retrying forever.
			sql: `DELETE FROM outbox WHERE id IN (
			          SELECT id FROM outbox
			          WHERE sent_at IS NULL AND created_at < $2
			          ORDER BY created_at LIMIT $1 FOR UPDATE SKIP LOCKED)`,
			args: func(now time.Time) []any { return []any{now.Add(-retention)} },
		},
	}
}

// RunOnce deletes one batch per table and returns how many rows went per
// table. Running it repeatedly drains a backlog.
func (j *Job) RunOnce(ctx context.Context) (map[string]int64, error) {
	now := j.clock.Now()
	deleted := map[string]int64{}
	for _, t := range j.tasks() {
		n, err := j.run(ctx, t, now)
		if err != nil {
			return deleted, err
		}
		deleted[t.name] = n
	}
	return deleted, nil
}

// run executes one task's delete.
func (j *Job) run(ctx context.Context, t task, now time.Time) (int64, error) {
	args := append([]any{j.batch}, t.args(now)...)
	res, err := database.Leader(ctx, j.db).ExecContext(ctx, t.sql, args...)
	if err != nil {
		return 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).
			WithMessage("cleanup: delete from " + t.name)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).
			WithMessage("cleanup: rows affected for " + t.name)
	}
	return n, nil
}

// Run repeats RunOnce on every tick until ctx is done. A pass that fills its
// batch is followed immediately by another, so a backlog drains instead of
// waiting a day per batch. A failure is logged and retried on the next tick,
// because losing the worker over a cleanup error would stop mail delivery too.
func (j *Job) Run(ctx context.Context, every time.Duration) error {
	if every <= 0 {
		every = DefaultInterval
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		j.drain(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// drain runs passes until no table fills its batch.
func (j *Job) drain(ctx context.Context) {
	for {
		deleted, err := j.RunOnce(ctx)
		if err != nil {
			j.log.ErrorWithContext(ctx, "cleanup pass failed", logger.F("error", err.Error()))
			return
		}
		total, full := int64(0), false
		for name, n := range deleted {
			total += n
			if n >= int64(j.batch) {
				full = true
			}
			if n > 0 {
				j.log.InfoWithContext(ctx, "cleanup deleted rows",
					logger.F("table", name), logger.F("rows", n))
			}
		}
		if total == 0 || !full || ctx.Err() != nil {
			return
		}
	}
}
