package invocation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestBatcherFlushesInBatchesAndKeepsRecordsOnSinkFailure(t *testing.T) {
	var mu sync.Mutex
	var got [][]Record
	fail := true
	b := NewBatcher(func(_ context.Context, batch []Record) error {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return errors.New("registry down")
		}
		got = append(got, batch)
		return nil
	}, nil)
	b.MaxBatch = 2
	for i := 0; i < 5; i++ {
		b.Record(Record{Tool: "t", Subject: "s"})
	}
	if err := b.Flush(context.Background()); err == nil || b.Pending() != 5 {
		t.Fatalf("failed flush must keep records: %v pending=%d", err, b.Pending())
	}
	fail = false
	if err := b.Flush(context.Background()); err != nil || b.Pending() != 0 {
		t.Fatal(err, b.Pending())
	}
	if len(got) != 3 || len(got[0]) != 2 || len(got[2]) != 1 {
		t.Fatalf("batches %v", got)
	}
}

func TestBatcherDropsAndCountsWhenFull(t *testing.T) {
	b := NewBatcher(func(context.Context, []Record) error { return nil }, nil)
	b.Capacity = 3
	for i := 0; i < 5; i++ {
		b.Record(Record{})
	}
	if b.Pending() != 3 || b.Dropped() != 2 {
		t.Fatalf("pending %d dropped %d", b.Pending(), b.Dropped())
	}
}

func TestRunFlushesOnShutdown(t *testing.T) {
	done := make(chan []Record, 1)
	b := NewBatcher(func(_ context.Context, batch []Record) error { done <- batch; return nil }, nil)
	b.Interval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	b.Record(Record{Tool: "last"})
	go b.Run(ctx)
	cancel()
	select {
	case batch := <-done:
		if batch[0].Tool != "last" {
			t.Fatal(batch)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending records lost on shutdown")
	}
}
