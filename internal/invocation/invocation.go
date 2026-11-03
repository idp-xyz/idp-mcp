// Package invocation records every tools/call the gateway decides on (ADR-0001 D11): who, what,
// the decision, the outcome and a digest of the arguments - never the arguments themselves.
// Records are batched and shipped asynchronously; the data path never blocks on the sink.
package invocation

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Decisions and outcomes.
const (
	Allow = "ALLOW"
	Deny  = "DENY"

	OutcomeOK           = "OK"            // upstream answered with a result
	OutcomeToolError    = "TOOL_ERROR"    // result with isError
	OutcomeRPCError     = "RPC_ERROR"     // upstream answered a JSON-RPC error
	OutcomeStreamed     = "STREAMED"      // SSE passed through; final status not inspected
	OutcomeNotDelivered = "NOT_DELIVERED" // never reached the upstream (dial refused, drift block)
	OutcomeUnknown      = "UNKNOWN"       // sent, but no answer (timeout, broken connection)
	OutcomeDenied       = "DENIED"
	OutcomeInvalidArgs  = "INVALID_ARGUMENTS" // refused before delivery: arguments violate the pinned inputSchema
)

// Record is one decision. Its JSON form is the published InvocationRecord contract (idp.telos.mcp
// 1.0.0, api/contracts/schema.json); internal/release's contract test keeps the two in step.
type Record struct {
	At            time.Time `json:"at"`
	ReleaseDigest string    `json:"releaseDigest"`
	Subject       string    `json:"subject"`
	Client        string    `json:"client,omitempty"` // OAuth client the token was issued to (azp)
	Actor         string    `json:"actor,omitempty"`  // delegated caller (RFC 8693 act), if any
	AuthMethod    string    `json:"authMethod"`
	Method        string    `json:"method"` // tools/call, prompts/get, resources/read, completion/complete, tasks/get|cancel|update
	Tool          string    `json:"tool"`   // exposed tool or prompt name, resource URI, completion ref or task id, as requested
	Target        string    `json:"target,omitempty"`
	Decision      string    `json:"decision"`
	Outcome       string    `json:"outcome"`
	LatencyMS     int64     `json:"latencyMs"`
	TraceID       string    `json:"traceId,omitempty"`
	ArgsDigest    string    `json:"argsDigest,omitempty"`
}

// Recorder accepts records without blocking.
type Recorder interface{ Record(Record) }

// Sink delivers a batch; an error keeps the batch for the next attempt.
type Sink func(ctx context.Context, batch []Record) error

// Batcher buffers records in memory up to Capacity and flushes them to Sink.
type Batcher struct {
	Sink     Sink
	Capacity int
	MaxBatch int
	Interval time.Duration
	Log      *slog.Logger

	mu      sync.Mutex
	pending []Record
	dropped atomic.Int64
	wake    chan struct{}
}

// NewBatcher returns a batcher with sensible bounds.
func NewBatcher(sink Sink, log *slog.Logger) *Batcher {
	return &Batcher{Sink: sink, Capacity: 10000, MaxBatch: 200, Interval: 2 * time.Second, Log: log, wake: make(chan struct{}, 1)}
}

// Record implements Recorder. When the buffer is full the record is dropped and counted; the drop
// count is reported in the gateway heartbeat so loss is visible, never silent.
func (b *Batcher) Record(r Record) {
	b.mu.Lock()
	if len(b.pending) >= b.Capacity {
		b.mu.Unlock()
		b.dropped.Add(1)
		return
	}
	b.pending = append(b.pending, r)
	full := len(b.pending) >= b.MaxBatch
	b.mu.Unlock()
	if full {
		select {
		case b.wake <- struct{}{}:
		default:
		}
	}
}

// Dropped returns how many records were lost to a full buffer.
func (b *Batcher) Dropped() int64 { return b.dropped.Load() }

// Pending returns the number of buffered records.
func (b *Batcher) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// Flush sends everything buffered, batch by batch, until the sink fails or the buffer is empty.
func (b *Batcher) Flush(ctx context.Context) error {
	for {
		b.mu.Lock()
		n := min(len(b.pending), b.MaxBatch)
		batch := append([]Record(nil), b.pending[:n]...)
		b.mu.Unlock()
		if n == 0 {
			return nil
		}
		if err := b.Sink(ctx, batch); err != nil {
			return err
		}
		b.mu.Lock()
		b.pending = b.pending[n:]
		b.mu.Unlock()
	}
}

// Run flushes periodically until ctx ends, then makes a final attempt.
func (b *Batcher) Run(ctx context.Context) {
	t := time.NewTicker(b.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := b.Flush(fctx); err != nil && b.Log != nil {
				b.Log.Warn("final invocation flush failed", "pending", b.Pending(), "err", err)
			}
			cancel()
			return
		case <-t.C:
		case <-b.wake:
		}
		if err := b.Flush(ctx); err != nil && b.Log != nil {
			b.Log.Warn("invocation flush failed; will retry", "pending", b.Pending(), "err", err)
		}
	}
}
