package main

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/lmdb"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/khatru/blossom"
	"fiatjaf.com/nostr/khatru/policies"
)

// getHTTPScheme returns the appropriate HTTP scheme based on the URL.
// Returns "http://" for .onion domains (Tor), "https://" for regular domains.
func getHTTPScheme(url string) string {
	if strings.Contains(url, ".onion") {
		return "http://"
	}
	return "https://"
}

// getWSScheme returns the appropriate WebSocket scheme based on the URL.
// Returns "ws://" for .onion domains (Tor), "wss://" for regular domains.
func getWSScheme(url string) string {
	if strings.Contains(url, ".onion") {
		return "ws://"
	}
	return "wss://"
}

// indexTemplate parses the relay landing page once, instead of on every
// request. It is html/template rather than text/template: the name and
// description it renders can be changed through the management API, so
// escaping them stops being optional.
var indexTemplate = sync.OnceValues(func() (*template.Template, error) {
	return template.ParseFiles("templates/index.html")
})

// relayIndexHandler serves one relay's landing page. name and description are
// the .env values; whatever the owner set over the management API wins.
func relayIndexHandler(relay, pubKey, name, description, wsURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		tmpl, err := indexTemplate()
		if err != nil {
			slog.Error("🚫 error parsing the relay landing page", "error", err)
			http.Error(w, "the relay landing page is unavailable", http.StatusInternalServerError)
			return
		}

		effectiveName, effectiveDescription, _ := effectiveRelayInfo(relay, name, description, "")
		data := struct {
			RelayName        string
			RelayPubkey      string
			RelayDescription string
			RelayURL         string
		}{
			RelayName:        effectiveName,
			RelayPubkey:      pubKey,
			RelayDescription: effectiveDescription,
			RelayURL:         wsURL,
		}

		// rendered whole before anything is written, so a failure halfway
		// through can still be reported as an error instead of a torn page
		var page bytes.Buffer
		if err := tmpl.Execute(&page, data); err != nil {
			slog.Error("🚫 error rendering the relay landing page", "relay", relay, "error", err)
			http.Error(w, "the relay landing page is unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write(page.Bytes()); err != nil {
			slog.Debug("🚫 error writing the relay landing page", "error", err)
		}
	}
}

//
// policy composition
//
// The monorepo khatru has one function per hook. These build that function
// out of an ordered list of policies, stopping at the first rejection, so each
// relay's rules read as a list again.
//

type eventPolicy = func(context.Context, *nostr.Event) (bool, string)
type filterPolicy = func(context.Context, nostr.Filter) (bool, string)
type connectionPolicy = func(*http.Request) bool

func chainEventPolicies(ps ...eventPolicy) func(context.Context, nostr.Event) (bool, string) {
	return func(ctx context.Context, event nostr.Event) (bool, string) {
		for _, p := range ps {
			if reject, msg := p(ctx, &event); reject {
				return reject, msg
			}
		}
		return false, ""
	}
}

func chainFilterPolicies(ps ...filterPolicy) filterPolicy {
	return func(ctx context.Context, filter nostr.Filter) (bool, string) {
		for _, p := range ps {
			if reject, msg := p(ctx, filter); reject {
				return reject, msg
			}
		}
		return false, ""
	}
}

func chainConnectionPolicies(ps ...connectionPolicy) connectionPolicy {
	return func(r *http.Request) bool {
		for _, p := range ps {
			if p(r) {
				return true
			}
		}
		return false
	}
}

// byValue adapts one of khatru's own event policies, which take the event by
// value, to the pointer form haven's policies use.
func byValue(p func(context.Context, nostr.Event) (bool, string)) eventPolicy {
	return func(ctx context.Context, event *nostr.Event) (bool, string) {
		return p(ctx, *event)
	}
}

// baseFilterPolicies are the filter-shape limits every relay applies.
func baseFilterPolicies(limits RelayLimits) []filterPolicy {
	var ps []filterPolicy
	if !limits.AllowEmptyFilters {
		ps = append(ps, policies.NoEmptyFilters)
	}
	if !limits.AllowComplexFilters {
		ps = append(ps, policies.NoComplexFilters)
	}
	return ps
}

// basePolicies are the checks every relay runs on an event before its own
// rules. The rate limiter is built here, once per relay: built inside the
// hook, as it used to be, it was a fresh token bucket for every event and so
// never limited anything.
func basePolicies(relay string, limits RelayLimits) []eventPolicy {
	return []eventPolicy{
		MustNotBeBannedToPost,
		MustNotBeABannedEvent(relay),
		MustBeAnAllowedKind(relay),
		byValue(policies.RejectEventsWithBase64Media),
		byValue(policies.EventIPRateLimiter(
			limits.EventIPLimiterTokensPerInterval,
			time.Minute*time.Duration(limits.EventIPLimiterInterval),
			limits.EventIPLimiterMaxTokens,
		)),
	}
}

func connectionPolicies(limits RelayLimits) connectionPolicy {
	return chainConnectionPolicies(
		MustNotBeIPBlocked,
		policies.ConnectionRateLimiter(
			limits.ConnectionRateLimiterTokensPerInterval,
			time.Minute*time.Duration(limits.ConnectionRateLimiterInterval),
			limits.ConnectionRateLimiterMaxTokens,
		),
	)
}

// setupRelayInfo fills in the NIP-11 fields every relay shares and returns the
// relay's pubkey as hex for its landing page.
func setupRelayInfo(relay *khatru.Relay, name, label, npub, description, icon, path string) string {
	pubKey := nostr.MustPubKeyFromHex(nPubToPubkey(label, npub))
	relay.Info.Name = name
	relay.Info.PubKey = &pubKey
	relay.Info.Description = description
	relay.Info.Icon = icon
	relay.Info.Version = config.RelayVersion
	relay.Info.Software = config.RelaySoftware
	relay.ServiceURL = getHTTPScheme(config.RelayURL) + config.RelayURL + path
	return pubKey.Hex()
}

var (
	privateRelay = khatru.NewRelay()
	privateDB    = newDBBackend("db/private")
)

var (
	chatRelay = khatru.NewRelay()
	chatDB    = newDBBackend("db/chat")
)

var (
	outboxRelay = khatru.NewRelay()
	outboxDB    = newDBBackend("db/outbox")
)

var (
	inboxRelay = khatru.NewRelay()
	inboxDB    = newDBBackend("db/inbox")
)

var blossomDB = newDBBackend("db/blossom")

var dbs = map[string]DBBackend{
	"blossom":    blossomDB,
	relayChat:    chatDB,
	relayInbox:   inboxDB,
	relayOutbox:  outboxDB,
	relayPrivate: privateDB,
}

type DBBackend = eventstore.Store

func newDBBackend(path string) DBBackend {
	switch config.DBEngine {
	case "lmdb":
		return newLMDBBackend(path)
	default:
		return newLMDBBackend(path)
	}
}

func newLMDBBackend(path string) *lmdb.LMDBBackend {
	return &lmdb.LMDBBackend{
		Path:    path,
		MapSize: config.LmdbMapSize,
	}
}

func initDBs() {
	for _, db := range []DBBackend{privateDB, chatDB, outboxDB, inboxDB, blossomDB} {
		if err := db.Init(); err != nil {
			panic(err)
		}
	}
}

func initRelays(ctx context.Context) {
	initDBs()

	loadBanList()

	initRelayLimits()

	// private
	privatePubKey := setupRelayInfo(privateRelay, config.PrivateRelayName, "PRIVATE_RELAY_NPUB", config.PrivateRelayNpub,
		config.PrivateRelayDescription, config.PrivateRelayIcon, "/private")

	privateRelay.OnRequest = chainFilterPolicies(append(baseFilterPolicies(privateRelayLimits),
		policies.MustAuth,
		MustBeWhitelistedToQuery,
	)...)
	privateRelay.OnEvent = chainEventPolicies(append(basePolicies(relayPrivate, privateRelayLimits),
		func(ctx context.Context, event *nostr.Event) (bool, string) {
			return EventMustBeLatest(ctx, event, privateDB)
		},
		MustBeWhitelistedToPost,
		MustNotBeDeleted(privateDB),
	)...)
	privateRelay.RejectConnection = connectionPolicies(privateRelayLimits)
	privateRelay.OnConnect = khatru.RequestAuth
	privateRelay.UseEventstore(privateDB, 1000)
	privateRelay.AllowDeleting = OwnerCanDeleteAnyEvent
	privateRelay.OverwriteRelayInformation = OverwriteRelayInfo(relayPrivate)
	instrument(privateRelay, relayPrivate)

	privateRelay.Router().HandleFunc("GET /private", relayIndexHandler(
		relayPrivate, privatePubKey, config.PrivateRelayName, config.PrivateRelayDescription,
		getWSScheme(config.RelayURL)+config.RelayURL+"/private",
	))

	// chat
	chatPubKey := setupRelayInfo(chatRelay, config.ChatRelayName, "CHAT_RELAY_NPUB", config.ChatRelayNpub,
		config.ChatRelayDescription, config.ChatRelayIcon, "/chat")

	chatRelay.OnRequest = chainFilterPolicies(append(baseFilterPolicies(chatRelayLimits),
		policies.MustAuth,
		MustBeInWotToQuery,
	)...)
	chatRelay.OnEvent = chainEventPolicies(append(basePolicies(relayChat, chatRelayLimits),
		MustNotBeBlacklistedToPost,
		MustBeInWotToPost,
		EventMustBeChatRelated,
		MustNotBeDeleted(chatDB),
	)...)
	chatRelay.RejectConnection = connectionPolicies(chatRelayLimits)
	chatRelay.OnConnect = khatru.RequestAuth
	chatRelay.UseEventstore(chatDB, 1000)
	chatRelay.AllowDeleting = OwnerCanDeleteAnyEvent
	chatRelay.OverwriteRelayInformation = OverwriteRelayInfo(relayChat)
	instrument(chatRelay, relayChat)

	chatRelay.Router().HandleFunc("GET /chat", relayIndexHandler(
		relayChat, chatPubKey, config.ChatRelayName, config.ChatRelayDescription,
		getWSScheme(config.RelayURL)+config.RelayURL+"/chat",
	))

	// outbox
	outboxPubKey := setupRelayInfo(outboxRelay, config.OutboxRelayName, "OUTBOX_RELAY_NPUB", config.OutboxRelayNpub,
		config.OutboxRelayDescription, config.OutboxRelayIcon, "")

	outboxRelay.OnRequest = chainFilterPolicies(baseFilterPolicies(outboxRelayLimits)...)
	outboxRelay.OnEvent = chainEventPolicies(append(basePolicies(relayOutbox, outboxRelayLimits),
		func(ctx context.Context, event *nostr.Event) (bool, string) {
			return EventMustBeLatest(ctx, event, outboxDB)
		},
		MustBeWhitelistedToPost,
		MustNotBeDeleted(outboxDB),
	)...)
	outboxRelay.RejectConnection = connectionPolicies(outboxRelayLimits)
	outboxRelay.UseEventstore(outboxDB, 1000)
	outboxRelay.AllowDeleting = OwnerCanDeleteAnyEvent
	outboxRelay.OverwriteRelayInformation = OverwriteRelayInfo(relayOutbox)
	outboxRelay.OnEventSaved = func(ctx context.Context, event nostr.Event) {
		refreshBanList(ctx, event)
		go blast(ctx, &event)
	}
	instrument(outboxRelay, relayOutbox)

	outboxRelay.Router().HandleFunc("GET /{$}", relayIndexHandler(
		relayOutbox, outboxPubKey, config.OutboxRelayName, config.OutboxRelayDescription,
		getWSScheme(config.RelayURL)+config.RelayURL+"/outbox",
	))

	initBlossom(ctx)

	// inbox
	inboxPubKey := setupRelayInfo(inboxRelay, config.InboxRelayName, "INBOX_RELAY_NPUB", config.InboxRelayNpub,
		config.InboxRelayDescription, config.InboxRelayIcon, "/inbox")

	inboxRelay.OnRequest = chainFilterPolicies(baseFilterPolicies(inboxRelayLimits)...)
	inboxRelay.OnEvent = chainEventPolicies(append(basePolicies(relayInbox, inboxRelayLimits),
		OnlyGiftWrappedDMs,
		EventMustNotBeFollowList,
		MustNotBeBlacklistedToPost,
		MustBeInWotToPost,
		MustTagWhitelistedPubKey,
		MustNotBeDeleted(inboxDB),
	)...)
	inboxRelay.RejectConnection = connectionPolicies(inboxRelayLimits)
	inboxRelay.UseEventstore(inboxDB, 1000)
	inboxRelay.AllowDeleting = OwnerCanDeleteAnyEvent
	inboxRelay.OverwriteRelayInformation = OverwriteRelayInfo(relayInbox)
	instrument(inboxRelay, relayInbox)

	inboxRelay.Router().HandleFunc("GET /inbox", relayIndexHandler(
		relayInbox, inboxPubKey, config.InboxRelayName, config.InboxRelayDescription,
		getWSScheme(config.RelayURL)+config.RelayURL+"/inbox",
	))
}

// initBlossom mounts the blob server on the outbox relay.
func initBlossom(ctx context.Context) {
	bl := blossom.New(outboxRelay, blobServiceURL())
	bl.Store = havenBlobIndex{
		EventStoreBlobIndexWrapper: blossom.EventStoreBlobIndexWrapper{Store: blossomDB, ServiceURL: bl.ServiceURL},
	}
	bl.StoreBlob = func(_ context.Context, sha256 string, ext string, body []byte) error {
		slog.Debug("storing blob", "sha256", sha256, "ext", ext)
		if err := writeBlob(sha256, body); err != nil {
			return err
		}
		blobInventory.invalidate()
		return nil
	}
	bl.LoadBlob = func(_ context.Context, sha256 string, ext string) (io.ReadSeeker, *url.URL, error) {
		slog.Debug("loading blob", "sha256", sha256, "ext", ext)
		file, err := fs.Open(blobPath(sha256))
		if err != nil {
			// serve the placeholder image rather than a bare error
			file, _ = fs.Open(config.BlossomPath + "404.png")
			return file, nil, err
		}
		return file, nil, nil
	}
	bl.DeleteBlob = func(_ context.Context, sha256 string, ext string) error {
		slog.Debug("deleting blob", "sha256", sha256, "ext", ext)
		removed, err := removeBlob(sha256)
		if removed {
			blobInventory.invalidate()
		}
		return err
	}
	bl.RejectUpload = func(_ context.Context, event *nostr.Event, size int, ext string) (bool, string, int) {
		// the whitelist check stays first: somebody who cannot upload at all
		// should never get to use this endpoint to find out whether a hash is
		// blocked
		if !isWhitelisted(event.PubKey.Hex()) {
			return true, "only media signed by whitelisted pubkeys are allowed", 403
		}
		// khatru hashes the body after this hook runs, so the only hash here is
		// the one the client declared in its authorization event. That gives a
		// well behaved client a clear refusal before it sends anything, while
		// havenBlobIndex.Keep is what actually enforces the block.
		for tag := range event.Tags.FindAll("x") {
			if len(tag) >= 2 && isBlockedBlob(strings.ToLower(strings.TrimSpace(tag[1]))) {
				return true, "this blob is blocked by the relay owner", 403
			}
		}
		return false, ext, size
	}
	// a blob that was blocked after it was stored stays on disk until the owner
	// deletes it, so this is what stops it being served in the meantime
	bl.RejectGet = func(_ context.Context, _ *nostr.Event, sha256 string, _ string) (bool, string, int) {
		if isBlockedBlob(sha256) {
			return true, "this blob has been removed by the relay owner", 410
		}
		return false, "", 0
	}
	instrumentBlossom(bl, relayOutbox)

	migrateBlossomMetadata(ctx, bl)
}
