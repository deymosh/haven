package main

import (
	"errors"
	"log/slog"

	"fiatjaf.com/nostr"
)

//
// walking an event store
//
// The traps this file works around are properties of the eventstore backend
// rather than of nostr, and each one fails silently rather than loudly, which
// is why they are written down here instead of being rediscovered:
//
//   1. Until is inclusive, so consecutive pages overlap at the cursor second
//      and the overlap has to be deduplicated by event id.
//   2. A short page does not mean the end of the walk when the walk was cut
//      short by visit or by the budget rather than by the store.
//   3. Setting Search does not perform a search and does not report that it
//      cannot — lmdb answers such a filter with an empty result.
//   4. The id index is keyed on the first eight bytes of the id, so an id
//      lookup verifies the full id itself before trusting the result.
//

// eventPageSize is how many events eachEvent fetches per query. The backend
// takes this as an explicit argument and honours it, so there is no hidden cap
// to stay below. It is a variable only so tests can shrink it and reach the
// multi-page paths with a few dozen events.
var eventPageSize = 1000

const (
	// maxEventScan bounds how many events one interactive call may examine.
	// Without a search string a listing examines roughly one event per row it
	// returns and this never bites; with one it is the only bound there is.
	// Because the cursor records where the scan stopped rather than where the
	// last match was, a search that runs out of budget resumes from there
	// instead of starting again.
	maxEventScan = 20000

	// maxAggregateScan bounds a whole-database walk — events by kind, top
	// authors, bytes stored. It is far larger than maxEventScan because it runs
	// on a timer rather than on a click, and because an aggregate that stops at
	// twenty thousand events is not an aggregate. Past this the caller reports
	// an incomplete result with the count it did manage, the way
	// buildBlobInventory already does.
	maxAggregateScan = 500000
)

// eventScanGate caps how many walks run at once.
//
// Every caller here is the authenticated owner, but the custom NIP-86 methods
// are answered in dynamicRelayHandler before khatru's rate limiters ever see
// them, so nothing else stands between a browser tab retrying in a loop and one
// walk per click sitting on the databases. Two at a time leaves the relay's own
// traffic somewhere to run.
var eventScanGate = make(chan struct{}, 2)

// errStoreCannotSearch is what a filter carrying a Search string earns. It is an
// error rather than a silent strip because the failure it prevents is invisible:
// lmdb answers such a filter by returning nothing at all, so the result would be
// an empty page reported beside a total in the thousands.
var errStoreCannotSearch = errors.New("this event store cannot search; the caller has to scan for itself")

// eachEvent walks every event matching filter, newest first, hands each one to
// visit exactly once, and reports how many distinct events it saw and whether it
// reached the end of the range.
//
// visit returns false to stop the walk; that is how a page fills up without
// scanning the rest of the database. complete is true only when the range was
// walked to its end, so a budget that ran out and a visit that asked to stop
// both report false and the caller has to say which.
//
// filter.Limit as the caller set it is ignored: paging is this function's
// business and every page is eventPageSize rows.
//
// The set of seen ids is deliberately not the whole walk. Until is inclusive, so
// the only events that can arrive twice are the ones sitting exactly on the
// cursor second — everything above it is outside the next query's range. Keeping
// only those bounds this by the busiest single second in the database instead of
// by the database: remembering every id of a two million event walk would be a
// quarter of a gigabyte held on the owner's request.
func eachEvent(
	db DBBackend,
	filter nostr.Filter,
	budget int,
	visit func(nostr.Event) bool,
) (scanned int, complete bool, err error) {
	if filter.Search != "" {
		return 0, false, errStoreCannotSearch
	}

	eventScanGate <- struct{}{}
	defer func() { <-eventScanGate }()

	// An id query is not paged and cannot be truncated: the planner ignores the
	// cursor bounds entirely when IDs is set, so a cursor walk would loop
	// forever refetching the same page, and GetTheoreticalLimit pins the limit
	// to len(IDs).
	if len(filter.IDs) > 0 {
		for evt := range db.QueryEvents(filter, len(filter.IDs)) {
			scanned++
			if !visit(evt) {
				return scanned, false, nil
			}
		}
		return scanned, true, nil
	}

	filter.Limit = eventPageSize

	// ids seen at exactly the cursor second, which is the only place a duplicate
	// can come from
	seen := make(map[nostr.ID]struct{})

	for {
		page := collectPage(db, filter)
		if len(page) == 0 {
			return scanned, true, nil
		}

		// computed rather than taken from the last element: nothing here should
		// depend on the order the backend happened to return
		oldest := page[0].CreatedAt
		for _, evt := range page {
			if evt.CreatedAt < oldest {
				oldest = evt.CreatedAt
			}
		}

		fresh := 0
		// rebuilt as the page is walked so it carries only the cursor second
		next := make(map[nostr.ID]struct{})
		for _, evt := range page {
			if evt.CreatedAt == oldest {
				next[evt.ID] = struct{}{}
			}
			if _, dupe := seen[evt.ID]; dupe {
				continue
			}
			fresh++
			scanned++
			if !visit(evt) {
				return scanned, false, nil
			}
			if budget > 0 && scanned >= budget {
				return scanned, false, nil
			}
		}

		if oldest <= 0 {
			return scanned, true, nil
		}

		if fresh == 0 {
			// Until is inclusive, so the last page of any walk comes back full of
			// events already seen. When that page was not full it is also proof
			// there is nothing older: the query asked for everything at or below
			// the cursor and did not fill a page, so this is the end.
			if len(page) < eventPageSize {
				return scanned, true, nil
			}

			// A full page of nothing new is the other story: more events share
			// this one second than a page can hold, and created_at is the finest
			// cursor there is. The only way to make progress is to step over that
			// second and lose whatever else was in it.
			slog.Warn("⚠️ more events share one second than a page holds, so some are being skipped",
				"until", int64(oldest), "page", len(page))
			oldest--
			if oldest <= 0 {
				return scanned, true, nil
			}
			// the cursor moved past the crowded second, so nothing carries over
			next = make(map[nostr.ID]struct{})
		}

		seen = next

		// terminating on a short page would be wrong: the page may have been cut
		// short by visit or by the budget rather than by the store, and this
		// loop must not stop before the walk is done
		filter.Until = oldest
	}
}

// collectPage reads one query into a slice. The monorepo backends yield through
// an iter.Seq, so stopping early unwinds cleanly and there is no channel to
// drain; collecting is simply the shape eachEvent wants.
func collectPage(db DBBackend, filter nostr.Filter) []nostr.Event {
	var page []nostr.Event
	for evt := range db.QueryEvents(filter, eventPageSize) {
		page = append(page, evt)
	}
	return page
}

// findStoredEvents reads events back out of one database by id, keyed by id and
// missing whatever was not there.
//
// It is one query rather than one per id: the planner builds a separate id-index
// lookup per id inside a single read transaction, and GetTheoreticalLimit pins
// the limit to len(ids).
//
// The id on each event is checked against what was asked for. The id index is
// keyed on the first eight bytes and neither the query nor DeleteEvent verify
// the rest, so a prefix collision would hand back — and delete — the wrong
// event. That is not something that happens, but this is the read a delete is
// built on and a compare is a small price for never deleting the wrong note.
func findStoredEvents(db DBBackend, ids []nostr.ID) (map[nostr.ID]nostr.Event, error) {
	found := make(map[nostr.ID]nostr.Event, len(ids))
	if len(ids) == 0 {
		return found, nil
	}

	wanted := make(map[nostr.ID]struct{}, len(ids))
	for _, id := range ids {
		wanted[id] = struct{}{}
	}

	_, _, err := eachEvent(db, nostr.Filter{IDs: ids, Limit: len(ids)}, 0, func(evt nostr.Event) bool {
		if _, ok := wanted[evt.ID]; ok {
			found[evt.ID] = evt
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}
