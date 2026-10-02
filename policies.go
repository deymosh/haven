package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip11"
	"github.com/deymosh/sanctum/pkg/wot"
)

func MustBeWhitelistedToQuery(ctx context.Context, _ nostr.Filter) (bool, string) {
	authenticatedUser, _ := khatru.GetAuthed(ctx)
	if !isWhitelisted(authenticatedUser.Hex()) {
		slog.Debug("🚫 query rejected: user is not whitelisted", "user", authenticatedUser)
		return true, "restricted: you must be whitelisted to query this relay"
	}
	return false, ""
}

func MustBeInWotToQuery(ctx context.Context, _ nostr.Filter) (bool, string) {
	authenticatedUser, _ := khatru.GetAuthed(ctx)
	if !wot.GetInstance().Has(ctx, authenticatedUser.Hex()) {
		slog.Debug("🚫 query rejected: user is not in the web of trust", "user", authenticatedUser)
		return true, "restricted: you must be in the web of trust to query this relay"
	}
	return false, ""
}

func MustBeWhitelistedToPost(ctx context.Context, event *nostr.Event) (bool, string) {
	// Event from a whitelisted pubkey can always be posted, even if the user is not authenticated
	if isWhitelisted(event.PubKey.Hex()) {
		return false, ""
	}
	authenticatedUser, ok := khatru.GetAuthed(ctx)
	if !ok {
		return true, "auth-required: you must be authenticated to post to this relay"
	}
	if !isWhitelisted(authenticatedUser.Hex()) {
		slog.Debug("🚫 event rejected: user is not whitelisted", "event", event.ID, "pubkey", authenticatedUser)
		return true, "restricted: you must be whitelisted to post to this relay"
	}
	return false, ""
}

func MustBeInWotToPost(ctx context.Context, event *nostr.Event) (bool, string) {
	// Event from a pubkey in the WoT can always be posted, even if the user is not authenticated
	if wot.GetInstance().Has(ctx, event.PubKey.Hex()) {
		return false, ""
	}
	authenticatedUser, ok := khatru.GetAuthed(ctx)
	if !ok {
		return true, "auth-required: you must be authenticated to post to this relay"
	}
	if !wot.GetInstance().Has(ctx, authenticatedUser.Hex()) {
		slog.Debug("🚫 event rejected: user is not in web of trust", "event", event.ID, "pubkey", authenticatedUser)
		return true, "you must be in the web of trust to post to this relay"
	}
	return false, ""
}

func MustNotBeBannedToPost(ctx context.Context, event *nostr.Event) (bool, string) {
	if isBanned(event.PubKey.Hex()) {
		slog.Debug("🚫 event rejected: event author is banned", "event", event.ID, "pubkey", event.PubKey)
		return true, "you are banned from this relay"
	}
	// gift wraps and the like are signed with throwaway keys, so check who is on
	// the other end of the connection too, when we know
	if authenticatedUser, ok := khatru.GetAuthed(ctx); ok && isBanned(authenticatedUser.Hex()) {
		slog.Debug("🚫 event rejected: authenticated user is banned", "event", event.ID, "pubkey", authenticatedUser)
		return true, "you are banned from this relay"
	}
	return false, ""
}

// MustNotBeIPBlocked drops websocket connections from addresses the owner
// blocked over the management API. It keys on the same address khatru's rate
// limiters do. It only covers websocket upgrades, which is all RejectConnection
// gets called for: a blocked address can still read the NIP-11 document, the
// landing page and blossom blobs.
func MustNotBeIPBlocked(r *http.Request) bool {
	ip := khatru.GetIPFromRequest(r)
	if !isBlockedIP(ip) {
		return false
	}
	slog.Debug("🚫 connection rejected: blocked IP", "ip", ip)
	return true
}

// MustBeAnAllowedKind enforces the kind rules set over the management API for
// one relay. An empty allow list means no allow list, or a relay would stop
// accepting everything the moment the state file appeared. The rules only ever
// narrow what a relay already accepts.
func MustBeAnAllowedKind(relay string) func(context.Context, *nostr.Event) (bool, string) {
	return func(_ context.Context, event *nostr.Event) (bool, string) {
		// the owner's delete requests always get through, or disallowing kind 5
		// would cost them the ability to delete anything
		if isOwnerDeleteRequest(event) {
			return false, ""
		}

		kind := int(event.Kind)
		rs := management.get().relayOrEmpty(relay)
		if slices.Contains(rs.DisallowedKinds, kind) {
			slog.Debug("🚫 event rejected: disallowed kind", "event", event.ID, "kind", kind)
			return true, fmt.Sprintf("kind %d is not accepted by this relay", kind)
		}
		if len(rs.AllowedKinds) > 0 && !slices.Contains(rs.AllowedKinds, kind) {
			slog.Debug("🚫 event rejected: kind is not on the allow list", "event", event.ID, "kind", kind)
			return true, fmt.Sprintf("kind %d is not accepted by this relay", kind)
		}
		return false, ""
	}
}

// MustNotBeABannedEvent rejects an event the owner banned over the management
// API. banevent deletes the stored copy; without this the next publish would
// simply put it back.
func MustNotBeABannedEvent(relay string) func(context.Context, *nostr.Event) (bool, string) {
	return func(_ context.Context, event *nostr.Event) (bool, string) {
		if isBannedEvent(relay, event.ID.Hex()) {
			slog.Debug("🚫 event rejected: event is banned", "event", event.ID, "relay", relay)
			return true, "this event is banned from this relay"
		}
		return false, ""
	}
}

// OverwriteRelayInfo applies the name, description and icon the owner set over
// the management API to a relay's NIP-11 document. khatru hands this hook a
// copy of rl.Info, so this is the race free place to change them.
func OverwriteRelayInfo(relay string) func(context.Context, *http.Request, nip11.RelayInformationDocument) nip11.RelayInformationDocument {
	return func(_ context.Context, _ *http.Request, info nip11.RelayInformationDocument) nip11.RelayInformationDocument {
		info.Name, info.Description, info.Icon = effectiveRelayInfo(relay, info.Name, info.Description, info.Icon)
		return info
	}
}

// isOwnerDeleteRequest reports whether the event is a NIP-09 delete request from
// the relay owner. Signatures are verified before any policy runs, so the pubkey
// on the event is proof enough that the owner sent it.
func isOwnerDeleteRequest(event *nostr.Event) bool {
	return event.Kind == nostr.KindDeletion && event.PubKey.Hex() == config.OwnerPubKey
}

func MustNotBeBlacklistedToPost(ctx context.Context, event *nostr.Event) (bool, string) {
	// The owner's delete requests carry the owner's signature, so there is nothing
	// left for an AUTH round trip to prove
	if isOwnerDeleteRequest(event) {
		return false, ""
	}

	// Events from a blacklisted pubkey ARE always rejected
	if _, ok := config.BlacklistedPubKeys[event.PubKey.Hex()]; ok {
		slog.Debug("🚫 event rejected: event author is blacklisted", "event", event.ID, "pubkey", event.PubKey)
		return true, "you are blacklisted from this relay"
	}
	// Still need auth due to GiftWrap and other events with random pubkeys
	authenticatedUser, ok := khatru.GetAuthed(ctx)
	if !ok {
		return true, "auth-required: you must be authenticated to post to this relay"
	}
	if _, ok := config.BlacklistedPubKeys[authenticatedUser.Hex()]; ok {
		slog.Debug("🚫 event rejected: authenticated user is blacklisted", "event", event.ID, "pubkey", authenticatedUser)
		return true, "you are blacklisted from this relay"
	}
	return false, ""
}

var allowedChatKinds = map[nostr.Kind]struct{}{
	// Regular kinds
	nostr.KindSimpleGroupChatMessage:   {},
	nostr.KindSimpleGroupThreadedReply: {},
	nostr.KindSimpleGroupThread:        {},
	nostr.KindSimpleGroupReply:         {},
	nostr.KindChannelMessage:           {},
	nostr.KindChannelHideMessage:       {},

	nostr.KindGiftWrap: {},

	nostr.KindSimpleGroupPutUser:      {},
	nostr.KindSimpleGroupRemoveUser:   {},
	nostr.KindSimpleGroupEditMetadata: {},
	nostr.KindSimpleGroupDeleteEvent:  {},
	nostr.KindSimpleGroupCreateGroup:  {},
	nostr.KindSimpleGroupDeleteGroup:  {},
	nostr.KindSimpleGroupCreateInvite: {},
	nostr.KindSimpleGroupJoinRequest:  {},
	nostr.KindSimpleGroupLeaveRequest: {},

	// Addressable kinds
	nostr.KindSimpleGroupMetadata: {},
	nostr.KindSimpleGroupAdmins:   {},
	nostr.KindSimpleGroupMembers:  {},
	nostr.KindSimpleGroupRoles:    {},
}

func EventMustBeChatRelated(_ context.Context, event *nostr.Event) (bool, string) {
	// the owner's delete requests are stored so the deletion survives a re-publish
	if isOwnerDeleteRequest(event) {
		return false, ""
	}

	if _, ok := allowedChatKinds[event.Kind]; ok {
		return false, ""
	}

	return true, "only chat related events are allowed"
}

func EventMustNotBeFollowList(_ context.Context, event *nostr.Event) (bool, string) {
	if event.Kind == nostr.KindFollowList {
		return true, "blocked: follow list events are not allowed"
	}
	return false, ""
}

func EventMustBeLatest(_ context.Context, event *nostr.Event, db eventstore.Store) (bool, string) {
	// if event is not replaceable or addressable kind, we don't need to check for latest
	if !event.Kind.IsReplaceable() && !event.Kind.IsAddressable() {
		return false, ""
	}

	// prepare filter with kind and author
	filter := nostr.Filter{
		Kinds:   []nostr.Kind{event.Kind},
		Authors: []nostr.PubKey{event.PubKey},
		Limit:   10, // could be just 1
	}

	// when addressable, add the "d" tag to the filter
	if event.Kind.IsAddressable() {
		filter.Tags = nostr.TagMap{"d": []string{event.Tags.GetD()}}
	}

	// query the latest events of the same kind and pubkey (and "d" tag if applicable)
	savedEvents := db.QueryEvents(filter, filter.Limit)

	// check if there is a stored event that is newer (or same precedence) than this incoming event
	for savedEvent := range savedEvents {
		if !nostr.IsOlder(savedEvent, *event) {
			slog.Debug("🚫 event rejected: there is a newer event", "kind", event.Kind, "pubkey", event.PubKey)
			return true, "replaced: there is a newer event"
		}
	}

	return false, ""
}

func OnlyGiftWrappedDMs(_ context.Context, event *nostr.Event) (bool, string) {
	if event.Kind == nostr.KindEncryptedDirectMessage {
		return true, "only gift wrapped DMs are supported"
	}
	return false, ""
}

func MustTagWhitelistedPubKey(_ context.Context, event *nostr.Event) (bool, string) {
	// the owner's delete requests are stored so the deletion survives a re-publish
	if isOwnerDeleteRequest(event) {
		return false, ""
	}

	// User must tag at least one whitelisted pubkey in this relay
	tags := event.Tags.FindAll("p")
	for tag := range tags {
		if len(tag) < 2 {
			continue
		}
		if isWhitelisted(tag[1]) {
			return false, ""
		}
	}

	slog.Debug("🚫 event rejected: event does not tag any whitelisted pubkey", "eventID", event.ID)

	return true, "you can only post notes if you've tagged a whitelisted pubkey in this relay"
}

// MustNotBeDeleted rejects events that have already been deleted from db, so a
// re-publish can't resurrect what the owner or the author deleted.
func MustNotBeDeleted(db DBBackend) func(context.Context, *nostr.Event) (bool, string) {
	return func(_ context.Context, event *nostr.Event) (bool, string) {
		if isDeleted(db, *event) {
			slog.Debug("🚫 event rejected: event has been deleted", "event", event.ID, "pubkey", event.PubKey)
			return true, "this event has been deleted"
		}
		return false, ""
	}
}
