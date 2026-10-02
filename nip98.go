package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"fiatjaf.com/nostr"
)

// nip98MaxClockSkew is how far the auth event's created_at may be from ours.
// NIP-98 suggests 60 seconds; we apply it in both directions, so a client with
// a fast clock fails loudly instead of being quietly accepted forever.
const nip98MaxClockSkew = 60

// verifyNIP98 validates the Authorization header of an HTTP request the way
// NIP-98 prescribes, with NIP-86's addition that the payload tag is mandatory
// rather than a SHOULD. It returns the pubkey that signed the auth event.
//
// khatru checks the signature, the u tag, the payload hash and the past side
// of the clock skew for its own NIP-86 handling, but not the auth event's
// kind or its method tag, so the custom-method dispatch checks all of it here.
func verifyNIP98(r *http.Request, body []byte, serviceURL string) (nostr.PubKey, error) {
	scheme, encoded, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Nostr") {
		return nostr.ZeroPK, errors.New("missing Nostr authorization header")
	}

	// the NIP-98 example header is unpadded, but plenty of clients pad
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		if decoded, err = base64.RawStdEncoding.DecodeString(encoded); err != nil {
			return nostr.ZeroPK, errors.New("authorization header is not valid base64")
		}
	}

	var event nostr.Event
	if err := json.Unmarshal(decoded, &event); err != nil {
		return nostr.ZeroPK, errors.New("authorization header is not a nostr event")
	}

	if event.Kind != nostr.KindHTTPAuth {
		return nostr.ZeroPK, fmt.Errorf("auth event must be kind %d, got %d", nostr.KindHTTPAuth, event.Kind)
	}
	if !event.CheckID() {
		return nostr.ZeroPK, errors.New("auth event id does not match its contents")
	}
	if !event.VerifySignature() {
		return nostr.ZeroPK, errors.New("auth event signature is invalid")
	}

	uTag := event.Tags.Find("u")
	if uTag == nil {
		return nostr.ZeroPK, errors.New("auth event has no u tag")
	}
	if !sameServiceURL(uTag[1], serviceURL) {
		return nostr.ZeroPK, fmt.Errorf("auth event u tag is %q, expected %q", uTag[1], serviceURL)
	}

	methodTag := event.Tags.Find("method")
	if methodTag == nil {
		return nostr.ZeroPK, errors.New("auth event has no method tag")
	}
	if !strings.EqualFold(methodTag[1], r.Method) {
		return nostr.ZeroPK, fmt.Errorf("auth event method tag is %q, expected %q", methodTag[1], r.Method)
	}

	sum := sha256.Sum256(body)
	payloadTag := event.Tags.Find("payload")
	if payloadTag == nil {
		return nostr.ZeroPK, errors.New("auth event has no payload tag")
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(payloadTag[1])), []byte(nostr.HexEncodeToString(sum[:]))) != 1 {
		return nostr.ZeroPK, errors.New("auth event payload tag does not match the request body")
	}

	now := nostr.Now()
	if event.CreatedAt < now-nip98MaxClockSkew || event.CreatedAt > now+nip98MaxClockSkew {
		return nostr.ZeroPK, fmt.Errorf("auth event created_at is %ds away from the relay's clock, more than the %ds allowed",
			abs64(int64(event.CreatedAt)-int64(now)), nip98MaxClockSkew)
	}

	return event.PubKey, nil
}

// sameServiceURL reports whether a NIP-98 u tag addresses this relay. The
// ws/wss distinction is dropped on purpose: sanctum sits behind a TLS terminating
// proxy and cannot know whether the client spoke http or https, and getHTTPScheme
// assumes https for anything that is not an onion address, so a plain HTTP
// deployment would otherwise never match. Host, port and path are what bind the
// auth event to one endpoint, and those are still compared.
func sameServiceURL(a, b string) bool {
	strip := func(u string) string {
		// NormalizeURL lowercases the host, drops a trailing slash and maps
		// http(s) onto ws(s); it returns "" for anything it cannot parse
		n := nostr.NormalizeURL(u)
		n = strings.TrimPrefix(n, "wss://")
		return strings.TrimPrefix(n, "ws://")
	}
	stripped := strip(a)
	return stripped != "" && stripped == strip(b)
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
