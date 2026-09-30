package main

import (
	"errors"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore/lmdb"
)

// newTestDB builds a real lmdb store in a temp directory with a deliberately
// tiny page size, so a few dozen events exercise the same multi-page eachEvent
// cursor walk that a real database only reaches in the tens of thousands.
func newTestDB(t *testing.T, pageSize int) DBBackend {
	t.Helper()
	db := &lmdb.LMDBBackend{
		Path: t.TempDir(),
		// small, because the default reserves 256GiB of address space and a test
		// has no use for it
		MapSize: 1 << 28,
	}
	if err := db.Init(); err != nil {
		t.Fatalf("init lmdb: %v", err)
	}
	t.Cleanup(db.Close)
	if pageSize > 0 {
		old := eventPageSize
		eventPageSize = pageSize
		t.Cleanup(func() { eventPageSize = old })
	}
	return db
}

// seedEvents stores one signed event per entry of createdAt and returns the ids
// in the order they were written.
func seedEvents(t *testing.T, db DBBackend, createdAt []nostr.Timestamp) []string {
	t.Helper()
	sk := nostr.Generate()
	ids := make([]string, 0, len(createdAt))
	for i, ts := range createdAt {
		evt := nostr.Event{
			CreatedAt: ts,
			Kind:      nostr.KindTextNote,
			Tags:      nostr.Tags{},
			Content:   string(rune('a'+i%26)) + "-note",
		}
		if err := evt.Sign(sk); err != nil {
			t.Fatalf("sign: %v", err)
		}
		if err := db.SaveEvent(evt); err != nil {
			t.Fatalf("save: %v", err)
		}
		ids = append(ids, evt.ID.Hex())
	}
	return ids
}

// TestEachEventVisitsEveryEventExactlyOnce is the test the whole file exists
// for. Until is inclusive, so every page after the first re-delivers whatever
// sat on the cursor second; a walk that forgets to deduplicate reports events
// twice, and one that steps the cursor back a second to avoid the overlap loses
// them instead. Both failures are silent.
func TestEachEventVisitsEveryEventExactlyOnce(t *testing.T) {
	db := newTestDB(t, 10)

	// spread over distinct seconds, so this is purely about page boundaries
	stamps := make([]nostr.Timestamp, 0, 95)
	for i := range 95 {
		stamps = append(stamps, nostr.Timestamp(1700000000+i))
	}
	want := seedEvents(t, db, stamps)

	counts := map[string]int{}
	scanned, complete, err := eachEvent(db, nostr.Filter{}, 0, func(evt nostr.Event) bool {
		counts[evt.ID.Hex()]++
		return true
	})
	if err != nil {
		t.Fatalf("eachEvent: %v", err)
	}
	if !complete {
		t.Error("walk reported incomplete over a range it walked to the end")
	}
	if scanned != len(want) {
		t.Errorf("scanned = %d, want %d", scanned, len(want))
	}
	for _, id := range want {
		switch counts[id] {
		case 1:
		case 0:
			t.Errorf("event %s was never visited", id[:8])
		default:
			t.Errorf("event %s was visited %d times", id[:8], counts[id])
		}
	}
}

// TestEachEventHandlesACrowdedSecond covers the case the walker warns about:
// more events sharing one second than a page can hold. created_at is the finest
// cursor there is, so the walk has to step over that second to make progress and
// some events are knowingly lost — but it must terminate, and it must not loop
// forever refetching the same page.
func TestEachEventHandlesACrowdedSecond(t *testing.T) {
	db := newTestDB(t, 4)

	stamps := make([]nostr.Timestamp, 0, 30)
	for range 20 {
		stamps = append(stamps, nostr.Timestamp(1700000500)) // all one second
	}
	for i := range 10 {
		stamps = append(stamps, nostr.Timestamp(1700000600+i))
	}
	seedEvents(t, db, stamps)

	seen := map[string]int{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, err := eachEvent(db, nostr.Filter{}, 0, func(evt nostr.Event) bool {
			seen[evt.ID.Hex()]++
			return true
		})
		if err != nil {
			t.Errorf("eachEvent: %v", err)
		}
	}()

	select {
	case <-done:
	case <-t.Context().Done():
		t.Fatal("eachEvent did not terminate on a crowded second")
	}

	for id, n := range seen {
		if n != 1 {
			t.Errorf("event %s visited %d times", id[:8], n)
		}
	}
	// the ten uncrowded events are above the crowded second and must all survive
	if len(seen) < 10 {
		t.Errorf("only %d distinct events visited; the events above the crowded second should all be there", len(seen))
	}
}

// TestEachEventStopsWhenVisitSaysSo is how a page fills up without scanning the
// rest of the database, so "stopped early" must not be reported as "reached the
// end".
func TestEachEventStopsWhenVisitSaysSo(t *testing.T) {
	db := newTestDB(t, 10)
	stamps := make([]nostr.Timestamp, 0, 40)
	for i := range 40 {
		stamps = append(stamps, nostr.Timestamp(1700000000+i))
	}
	seedEvents(t, db, stamps)

	n := 0
	scanned, complete, err := eachEvent(db, nostr.Filter{}, 0, func(nostr.Event) bool {
		n++
		return n < 7
	})
	if err != nil {
		t.Fatalf("eachEvent: %v", err)
	}
	if complete {
		t.Error("complete was true after visit asked to stop")
	}
	if scanned != 7 || n != 7 {
		t.Errorf("scanned = %d, visits = %d, want 7 and 7", scanned, n)
	}
}

// TestEachEventRespectsTheBudget: the budget is the only thing bounding a
// content search, so running out of it must be reported as not-complete rather
// than as an honest end of range.
func TestEachEventRespectsTheBudget(t *testing.T) {
	db := newTestDB(t, 10)
	stamps := make([]nostr.Timestamp, 0, 40)
	for i := range 40 {
		stamps = append(stamps, nostr.Timestamp(1700000000+i))
	}
	seedEvents(t, db, stamps)

	scanned, complete, err := eachEvent(db, nostr.Filter{}, 12, func(nostr.Event) bool {
		return true
	})
	if err != nil {
		t.Fatalf("eachEvent: %v", err)
	}
	if complete {
		t.Error("complete was true after the budget ran out")
	}
	if scanned != 12 {
		t.Errorf("scanned = %d, want the budget of 12", scanned)
	}
}

// TestEachEventRefusesToSearch guards the trap that motivated errStoreCannotSearch:
// lmdb answers a filter carrying Search by returning nothing at all, so passing
// one through would report an empty result as a real one.
func TestEachEventRefusesToSearch(t *testing.T) {
	db := newTestDB(t, 10)
	seedEvents(t, db, []nostr.Timestamp{1700000000})

	_, _, err := eachEvent(db, nostr.Filter{Search: "anything"}, 0, func(nostr.Event) bool {
		t.Error("visit ran for a filter carrying a search string")
		return true
	})
	if !errors.Is(err, errStoreCannotSearch) {
		t.Errorf("err = %v, want errStoreCannotSearch", err)
	}
}

// TestFindStoredEventsReturnsWholeEvents: the lookup must return the full stored
// event — signature and author alike — and it must not invent entries for ids
// that were never stored.
func TestFindStoredEventsReturnsWholeEvents(t *testing.T) {
	db := newTestDB(t, 10)
	ids := seedEvents(t, db, []nostr.Timestamp{1700000001, 1700000002, 1700000003})

	missing := "0000000000000000000000000000000000000000000000000000000000000000"
	parsed := make([]nostr.ID, 0, len(ids))
	for _, id := range ids {
		parsed = append(parsed, nostr.MustIDFromHex(id))
	}
	found, err := findStoredEvents(db, append(parsed, nostr.MustIDFromHex(missing)))
	if err != nil {
		t.Fatalf("findStoredEvents: %v", err)
	}
	if len(found) != len(ids) {
		t.Errorf("found %d events, want %d", len(found), len(ids))
	}
	for _, id := range ids {
		key := nostr.MustIDFromHex(id)
		evt, ok := found[key]
		if !ok {
			t.Errorf("event %s was not found", id[:8])
			continue
		}
		if evt.ID != key {
			t.Errorf("event keyed %s carries id %s", id[:8], evt.ID.Hex()[:8])
		}
		if evt.Sig == [64]byte{} || evt.PubKey.Hex() == "" {
			t.Errorf("event %s came back without its signature or author", id[:8])
		}
	}
	if _, ok := found[nostr.MustIDFromHex(missing)]; ok {
		t.Error("an id that was never stored came back")
	}
}
