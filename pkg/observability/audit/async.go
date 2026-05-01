package audit

import (
	"context"
	"log/slog"
	"sync/atomic"
)

// AsyncSink wraps a Sink with a buffered channel so Record() never
// blocks the auth hot path. Events are delivered best-effort: if the
// buffer is full, the event is dropped and a drop counter is incremented.
// Call Close() to flush remaining events on shutdown.
type AsyncSink struct {
	inner      Sink
	ch         chan *Event
	done       chan struct{}
	dropped    atomic.Int64
	loggedDrop atomic.Bool
}

// AsyncSinkOption configures an AsyncSink.
type AsyncSinkOption func(*AsyncSink)

// NewAsyncSink wraps inner with an async buffer of the given size.
// A background goroutine drains the channel. Default buffer size is 4096.
func NewAsyncSink(inner Sink, bufSize int) *AsyncSink {
	if bufSize <= 0 {
		bufSize = 4096
	}
	a := &AsyncSink{
		inner: inner,
		ch:    make(chan *Event, bufSize),
		done:  make(chan struct{}),
	}
	go a.drain()
	return a
}

// Record implements Sink. Non-blocking: drops on full buffer.
func (a *AsyncSink) Record(_ context.Context, e *Event) {
	select {
	case a.ch <- e:
	default:
		n := a.dropped.Add(1)
		// AUD3: Log warning on first drop so operators notice.
		if a.loggedDrop.CompareAndSwap(false, true) {
			slog.Warn("audit: async buffer full, dropping events", "dropped", n, "bufSize", cap(a.ch))
		}
	}
}

// Dropped returns the number of events dropped due to back-pressure.
func (a *AsyncSink) Dropped() int64 {
	return a.dropped.Load()
}

// Close signals the drain goroutine to flush and exit. Blocks until
// all buffered events are delivered.
func (a *AsyncSink) Close() {
	close(a.ch)
	<-a.done
}

func (a *AsyncSink) drain() {
	defer close(a.done)
	for e := range a.ch {
		a.inner.Record(context.Background(), e)
	}
}
