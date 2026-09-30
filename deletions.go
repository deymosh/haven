package main

import (
	"context"
	"fmt"
	"log/slog"

	"fiatjaf.com/nostr"
)

// isDeleted reports whether db holds a NIP-09 delete request covering the event.
//
// The import paths write to the databases directly and don't check at all, and
// without this a deleted note comes straight back on the next publish or on the
// next pull from the seed relays.
func isDeleted(db DBBackend, event nostr.Event) bool {
	// only the author of an event and the relay owner can delete it, so a delete
	// request from anybody else doesn't count
	authors := []nostr.PubKey{event.PubKey, nostr.MustPubKeyFromHex(config.OwnerPubKey)}

	filters := []nostr.Filter{{
		Kinds:   []nostr.Kind{nostr.KindDeletion},
		Authors: authors,
		Tags:    nostr.TagMap{"e": []string{event.ID.Hex()}},
		Limit:   1,
	}}

	// replaceable and addressable events are also deleted by address, and such a
	// request only covers the versions that existed when it was made
	if !event.Kind.IsRegular() {
		address := fmt.Sprintf("%d:%s:%s", event.Kind, event.PubKey.Hex(), event.Tags.GetD())
		filters = append(filters, nostr.Filter{
			Kinds:   []nostr.Kind{nostr.KindDeletion},
			Authors: authors,
			Tags:    nostr.TagMap{"a": []string{address}},
			Since:   event.CreatedAt,
			Limit:   1,
		})
	}

	for _, filter := range filters {
		for range db.QueryEvents(filter, filter.Limit) {
			return true
		}
	}

	return false
}

// OwnerCanDeleteAnyEvent replaces khatru's default NIP-09 outcome, which only
// lets authors delete their own events, so that the owner can delete anything
// stored on their relay. Everybody else is still limited to their own events.
//
// It is wired into AllowDeleting, the monorepo khatru hook that replaces the
// old OverwriteDeletionOutcome: returning true allows the deletion.
func OwnerCanDeleteAnyEvent(_ context.Context, target nostr.Event, deletion nostr.Event) bool {
	if isBanned(deletion.PubKey.Hex()) {
		slog.Debug("🚫 deletion rejected: user is banned", "event", target.ID, "pubkey", deletion.PubKey)
		return false
	}

	if target.PubKey == deletion.PubKey {
		return true
	}

	if deletion.PubKey.Hex() == config.OwnerPubKey {
		slog.Info("🗑️ owner deleted an event", "event", target.ID, "kind", target.Kind, "author", target.PubKey)
		return true
	}

	slog.Debug("🚫 deletion rejected: user is not the author of the event", "event", target.ID, "pubkey", deletion.PubKey)
	return false
}
