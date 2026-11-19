package admission

import (
	"sync"
	"time"
)

// Limiter is a sliding-window request limiter held in memory (ADR-0001 D49). It is per replica, as idp-web's
// is: with several replicas the effective limit is the number of replicas times the configured one, and a
// restart forgets the window. That is enough to stop a runaway client; it is not a quota.
type Limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*bucket
}

// bucket is the requests of one key inside its window; the window is kept with them so that an idle key can be
// dropped by its own measure.
type bucket struct {
	hits   []time.Time
	window time.Duration
}

// NewLimiter returns a limiter reading the clock from now (time.Now when nil).
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, buckets: map[string]*bucket{}}
}

// maxKeys bounds the table: past it, the keys whose requests are all out of their window are dropped.
const maxKeys = 10000

// Allow records a request under key and returns 0, or, when key is over limit within its window, how long
// to wait until the oldest request leaves the window; a refused request is not recorded. The key names the
// dimension, for example "client\x00idp-host".
func (l *Limiter) Allow(key string, lim Limit) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxKeys {
			for k, o := range l.buckets {
				if len(o.hits) == 0 || now.Sub(o.hits[len(o.hits)-1]) >= o.window {
					delete(l.buckets, k)
				}
			}
		}
		b = &bucket{}
		l.buckets[key] = b
	}
	b.window = lim.Window
	i := 0
	for i < len(b.hits) && now.Sub(b.hits[i]) >= lim.Window {
		i++
	}
	b.hits = b.hits[i:]
	if len(b.hits) >= lim.Requests {
		return max(b.hits[0].Add(lim.Window).Sub(now), time.Millisecond)
	}
	b.hits = append(b.hits, now)
	return 0
}
