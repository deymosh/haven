package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/khatru/blossom"
	"github.com/puzpuzpuz/xsync/v4"
)

//
// counting what the relay does
//
// The monorepo khatru has one function per hook rather than a slice of them, so
// instrumenting a relay means wrapping whatever policy is already installed: the
// wrapper counts the attempt, asks the policy, and counts a pass only when the
// policy did not reject. No ordering tricks are needed and the "passed" counters
// can never sit in front of a policy by mistake.
//
// The counters are monotonic for the life of the process and are never reset.
// The flusher keeps the previous reading and stores the difference, which removes
// the entire class of bug where a reset races with an increment.
//

type counter int

// Entries may only ever be APPENDED. The name is what goes on disk and on the
// wire, so inserting one in the middle would silently re-label every bucket
// already written.
const (
	uptimeSeconds counter = iota

	connAttempts
	connAllowed
	connOpened
	connClosed
	connSeconds

	eventAttempts
	eventPassed
	eventStored
	eventBytes
	eventImported

	reqFilters
	reqSubscribeOnly
	reqPassed
	countFilters

	blobUploadAttempts
	blobUploadAllowed
	blobStored
	blobBytes
	blobServed
	blobDeleted

	counterCount
)

var counterNames = [counterCount]string{
	uptimeSeconds:      "uptime_seconds",
	connAttempts:       "conn_attempts",
	connAllowed:        "conn_allowed",
	connOpened:         "conn_opened",
	connClosed:         "conn_closed",
	connSeconds:        "conn_seconds",
	eventAttempts:      "event_attempts",
	eventPassed:        "event_passed",
	eventStored:        "event_stored",
	eventBytes:         "event_bytes",
	eventImported:      "event_imported",
	reqFilters:         "req_filters",
	reqSubscribeOnly:   "req_subscribe_only",
	reqPassed:          "req_passed",
	countFilters:       "count_filters",
	blobUploadAttempts: "blob_upload_attempts",
	blobUploadAllowed:  "blob_upload_allowed",
	blobStored:         "blob_stored",
	blobBytes:          "blob_bytes",
	blobServed:         "blob_served",
	blobDeleted:        "blob_deleted",
}

// counters is one relay's running totals. A plain atomic.Int64 is plenty for a
// personal relay doing tens of events a second.
type counters [counterCount]atomic.Int64

type sample [counterCount]int64

func (c *counters) add(k counter, n int64) { c[k].Add(n) }

func (c *counters) sample() sample {
	var s sample
	for i := range c {
		s[i] = c[i].Load()
	}
	return s
}

// relayMetrics is everything counted for one relay.
type relayMetrics struct {
	name       string
	c          counters
	kinds      *xsync.Map[int, *atomic.Int64]
	kindsOther atomic.Int64

	// conns is the live connection set, keyed on the websocket. khatru runs
	// OnDisconnect once per connection behind a sync.Once, but keying on the
	// socket keeps the open/closed pair balanced whatever the library does.
	conns *xsync.Map[*khatru.WebSocket, time.Time]
}

func newRelayMetrics(name string) *relayMetrics {
	return &relayMetrics{
		name:  name,
		kinds: xsync.NewMap[int, *atomic.Int64](),
		conns: xsync.NewMap[*khatru.WebSocket, time.Time](),
	}
}

func (m *relayMetrics) recordKind(kind int) {
	if n, ok := m.kinds.Load(kind); ok {
		n.Add(1)
		return
	}
	// the cap stops somebody publishing ten thousand distinct kinds from turning
	// this map into the relay's memory profile. It is read without a lock, so it
	// can be overshot by a few under concurrency: it is a bound, not an invariant.
	if m.kinds.Size() >= config.AnalyticsMaxKinds {
		m.kindsOther.Add(1)
		return
	}
	n, _ := m.kinds.LoadOrStore(kind, &atomic.Int64{})
	n.Add(1)
}

func (m *relayMetrics) kindSnapshot() map[int]int64 {
	out := make(map[int]int64)
	m.kinds.Range(func(kind int, n *atomic.Int64) bool {
		out[kind] = n.Load()
		return true
	})
	return out
}

// approxEventBytes estimates what one event costs to store. It is an estimate
// and is labelled as one everywhere it surfaces: serialising every accepted event
// purely to measure it would allocate a second copy of the relay's write traffic.
func approxEventBytes(evt nostr.Event) int64 {
	// id, pubkey and sig are fixed width hex; the rest is JSON punctuation and
	// the kind and timestamp
	n := int64(len(evt.Content)) + 220
	for _, tag := range evt.Tags {
		for _, item := range tag {
			n += int64(len(item)) + 3
		}
	}
	return n
}

// instrument wires one relay into the metrics store.
//
// It MUST be called after every policy for the relay has been installed: it
// wraps the hooks it finds, so a policy installed afterwards would replace the
// wrapper and go uncounted.
func instrument(relay *khatru.Relay, name string) {
	if !config.AnalyticsEnabled {
		return
	}
	m := metrics.relay(name)

	rejectConnection := relay.RejectConnection
	relay.RejectConnection = func(r *http.Request) bool {
		m.c.add(connAttempts, 1)
		if rejectConnection != nil && rejectConnection(r) {
			return true
		}
		m.c.add(connAllowed, 1)
		return false
	}

	// conn_allowed means "passed every RejectConnection policy", which is not the
	// same as connected: the websocket upgrade itself can still fail afterwards.
	// OnConnect is the one that means connected.
	onConnect := relay.OnConnect
	relay.OnConnect = func(ctx context.Context) {
		if ws := khatru.GetConnection(ctx); ws != nil {
			m.conns.Store(ws, time.Now())
			m.c.add(connOpened, 1)
		}
		if onConnect != nil {
			onConnect(ctx)
		}
	}
	onDisconnect := relay.OnDisconnect
	relay.OnDisconnect = func(ctx context.Context) {
		if ws := khatru.GetConnection(ctx); ws != nil {
			if at, ok := m.conns.LoadAndDelete(ws); ok {
				m.c.add(connClosed, 1)
				m.c.add(connSeconds, int64(time.Since(at).Seconds()))
			}
		}
		if onDisconnect != nil {
			onDisconnect(ctx)
		}
	}

	onEvent := relay.OnEvent
	relay.OnEvent = func(ctx context.Context, event nostr.Event) (bool, string) {
		m.c.add(eventAttempts, 1)
		if onEvent != nil {
			if reject, msg := onEvent(ctx, event); reject {
				return reject, msg
			}
		}
		m.c.add(eventPassed, 1)
		return false, ""
	}

	// event_passed is not event_stored, and the gap is not an error: a duplicate
	// is answered OK and never written, and an ephemeral event is never written
	// at all. OnEventSaved fires once per event that actually reached the
	// database, covering both the store and the replace branch.
	onEventSaved := relay.OnEventSaved
	relay.OnEventSaved = func(ctx context.Context, event nostr.Event) {
		m.c.add(eventStored, 1)
		m.c.add(eventBytes, approxEventBytes(event))
		m.recordKind(int(event.Kind))
		if onEventSaved != nil {
			onEventSaved(ctx, event)
		}
	}

	// OnRequest runs before khatru looks at LimitZero, so a subscribe-only REQ
	// is visible here too.
	onRequest := relay.OnRequest
	relay.OnRequest = func(ctx context.Context, filter nostr.Filter) (bool, string) {
		m.c.add(reqFilters, 1)
		if filter.LimitZero {
			m.c.add(reqSubscribeOnly, 1)
		}
		if onRequest != nil {
			if reject, msg := onRequest(ctx, filter); reject {
				return reject, msg
			}
		}
		m.c.add(reqPassed, 1)
		return false, ""
	}

	// COUNT has its own hook and haven installs no policy on it, so this is the
	// only visibility there is into NIP-45 traffic.
	onCount := relay.OnCount
	relay.OnCount = func(ctx context.Context, filter nostr.Filter) (bool, string) {
		m.c.add(countFilters, 1)
		if onCount != nil {
			return onCount(ctx, filter)
		}
		return false, ""
	}
}

// instrumentBlossom counts media traffic. Blossom hangs off the outbox relay
// alone, so all of this lands in the outbox relay's counters. Like instrument,
// it must run after haven's own blossom hooks are installed.
func instrumentBlossom(bl *blossom.BlossomServer, name string) {
	if !config.AnalyticsEnabled {
		return
	}
	m := metrics.relay(name)

	// RejectUpload runs for HEAD /upload as well as the real PUT, so this counts
	// attempts including the check a well behaved client makes before sending
	// anything.
	rejectUpload := bl.RejectUpload
	bl.RejectUpload = func(ctx context.Context, auth *nostr.Event, size int, ext string) (bool, string, int) {
		m.c.add(blobUploadAttempts, 1)
		if rejectUpload == nil {
			m.c.add(blobUploadAllowed, 1)
			return false, ext, size
		}
		// the second and third results are passed through untouched either way
		reject, msg, code := rejectUpload(ctx, auth, size, ext)
		if !reject {
			m.c.add(blobUploadAllowed, 1)
		}
		return reject, msg, code
	}

	storeBlob := bl.StoreBlob
	bl.StoreBlob = func(ctx context.Context, sha256 string, ext string, body []byte) error {
		if err := storeBlob(ctx, sha256, ext, body); err != nil {
			return err
		}
		m.c.add(blobStored, 1)
		m.c.add(blobBytes, int64(len(body)))
		return nil
	}

	loadBlob := bl.LoadBlob
	bl.LoadBlob = func(ctx context.Context, sha256 string, ext string) (io.ReadSeeker, *url.URL, error) {
		m.c.add(blobServed, 1)
		return loadBlob(ctx, sha256, ext)
	}

	deleteBlob := bl.DeleteBlob
	bl.DeleteBlob = func(ctx context.Context, sha256 string, ext string) error {
		if err := deleteBlob(ctx, sha256, ext); err != nil {
			return err
		}
		m.c.add(blobDeleted, 1)
		return nil
	}
}
