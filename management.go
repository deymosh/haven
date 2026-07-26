package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip86"
)

func SetupManagementAPI(relay *khatru.Relay) {
	relay.ManagementAPI.AllowPubKey = AllowPubKey
	relay.ManagementAPI.UnallowPubKey = UnallowPubKey
	relay.ManagementAPI.ListAllowedPubKeys = ListAllowedPubKeys

	relay.ManagementAPI.BanPubKey = BanPubKey
	relay.ManagementAPI.UnbanPubKey = UnbanPubKey
	relay.ManagementAPI.ListBannedPubKeys = ListBannedPubKeys

	relay.ManagementAPI.Stats = Stats
	relay.ManagementAPI.ChangeRelayIcon = ChangeRelayIcon
}

// RejectAPICall helper function to determine if the API call should be rejected based on the authenticated public key
func RejectAPICall(ctx context.Context) (reject bool, caller nostr.PubKey) {
	authed, _ := khatru.GetAuthed(ctx)
	if authed.Hex() != config.OwnerPubKey {
		return true, authed
	}

	return false, authed
}

// AllowPubKey adds a public key to the whitelist and persists it to the file
func AllowPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	reject, authed := RejectAPICall(ctx)
	if reject {
		slog.Warn("unauthorized attempt to allow pubkey", "caller", authed.Hex(), "pubkey", pubkey.Hex(), "reason", reason)
		return errors.New("unauthorized: only the relay owner can allow pubkeys")
	}

	slog.Debug("allowing pubkey", "pubkey", pubkey.Hex(), "reason", reason)

	hex := pubkey.Hex()
	config.WhitelistedPubKeys[hex] = struct{}{}

	// Persist changes to the file if configured
	filePath := getEnvString("WHITELISTED_NPUBS_FILE", "")
	if filePath != "" {
		savePubKeysToFile(filePath, config.WhitelistedPubKeys)
	}

	return nil
}

// UnallowPubKey removes a public key from the whitelist and persists the changes
func UnallowPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	reject, authed := RejectAPICall(ctx)
	if reject {
		slog.Warn("unauthorized attempt to unallow pubkey", "caller", authed.Hex(), "pubkey", pubkey.Hex(), "reason", reason)
		return errors.New("unauthorized: only the relay owner can unallow pubkeys")
	}

	slog.Debug("unallowing pubkey", "pubkey", pubkey.Hex(), "reason", reason)
	
	hex := pubkey.Hex()
	if hex == config.OwnerPubKey {
		slog.Warn("attempted to unallow relay owner pubkey, action blocked", "pubkey", hex)
		return nil
	}

	delete(config.WhitelistedPubKeys, hex)

	// Persist changes to the file if configured
	filePath := getEnvString("WHITELISTED_NPUBS_FILE", "")
	if filePath != "" {
		savePubKeysToFile(filePath, config.WhitelistedPubKeys)
	}

	return nil
}

// ListAllowedPubKeys returns all currently whitelisted public keys
func ListAllowedPubKeys(ctx context.Context) ([]nip86.PubKeyReason, error) {
	reject, authed := RejectAPICall(ctx)
	if reject {
		slog.Warn("unauthorized attempt to list allowed pubkeys", "caller", authed.Hex())
		return nil, errors.New("unauthorized: only the relay owner can list allowed pubkeys")
	}

	slog.Debug("listing allowed pubkeys via NIP-86")

	var allowed []nip86.PubKeyReason
	for pubkey := range config.WhitelistedPubKeys {
		allowed = append(allowed, nip86.PubKeyReason{
			PubKey: nostr.MustPubKeyFromHex(pubkey),
			Reason: "whitelisted",
		})
	}

	return allowed, nil
}

// BanPubKey adds a public key to the blacklist and persists it to the file
func BanPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	reject, authed := RejectAPICall(ctx)
	if reject {
		slog.Warn("unauthorized attempt to ban pubkey", "caller", authed.Hex(), "pubkey", pubkey.Hex(), "reason", reason)
		return errors.New("unauthorized: only the relay owner can ban pubkeys")
	}

	slog.Debug("banning pubkey", "pubkey", pubkey.Hex(), "reason", reason)
	
	hex := pubkey.Hex()
	if hex == config.OwnerPubKey {
		slog.Warn("attempted to ban relay owner pubkey, action blocked", "pubkey", hex)
		return nil
	}

	config.BlacklistedPubKeys[hex] = struct{}{}

	// Persist changes to the file if configured
	filePath := getEnvString("BLACKLISTED_NPUBS_FILE", "")
	if filePath != "" {
		savePubKeysToFile(filePath, config.BlacklistedPubKeys)
	}

	return nil
}

// UnbanPubKey removes a public key from the blacklist and persists the changes
func UnbanPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	reject, authed := RejectAPICall(ctx)
	if reject {
		slog.Warn("unauthorized attempt to unban pubkey", "caller", authed.Hex(), "pubkey", pubkey.Hex(), "reason", reason)
		return errors.New("unauthorized: only the relay owner can unban pubkeys")
	}

	slog.Debug("unbanning pubkey", "pubkey", pubkey.Hex(), "reason", reason)
	
	hex := pubkey.Hex()
	delete(config.BlacklistedPubKeys, hex)

	// Persist changes to the file if configured
	filePath := getEnvString("BLACKLISTED_NPUBS_FILE", "")
	if filePath != "" {
		savePubKeysToFile(filePath, config.BlacklistedPubKeys)
	}

	return nil
}

// ListBannedPubKeys returns all currently blacklisted public keys
func ListBannedPubKeys(ctx context.Context) ([]nip86.PubKeyReason, error) {
	reject, authed := RejectAPICall(ctx)
	if reject {
		slog.Warn("unauthorized attempt to list banned pubkeys", "caller", authed.Hex())
		return nil, errors.New("unauthorized: only the relay owner can list banned pubkeys")
	}

	slog.Debug("listing banned pubkeys via NIP-86")

	var banned []nip86.PubKeyReason
	for pubkey := range config.BlacklistedPubKeys {
		banned = append(banned, nip86.PubKeyReason{
			PubKey: nostr.MustPubKeyFromHex(pubkey),
			Reason: "blacklisted",
		})
	}

	return banned, nil
}

// ChangeRelayIcon updates all relays' icon URLs and persists them to the .env file
func ChangeRelayIcon(ctx context.Context, iconURL string) error {
	reject, authed := RejectAPICall(ctx)
	if reject {
		slog.Warn("unauthorized attempt to change relay icon", "caller", authed.Hex(), "icon", iconURL)
		return errors.New("unauthorized: only the relay owner can change the relay icon")
	}

	slog.Debug("changing relay icon for all relays", "icon", iconURL)

	relays := map[string]*khatru.Relay{
		"PRIVATE": privateRelay,
		"CHAT":    chatRelay,
		"INBOX":   inboxRelay,
		"OUTBOX":  outboxRelay,
	}

	filePath := getEnvString("ENV_FILE_PATH", ".env")

	for prefix, relay := range relays {
		if relay != nil {
			relay.Info.Icon = iconURL
		}
		envKey := prefix + "_RELAY_ICON"
		updateEnvFileString(filePath, envKey, iconURL)
	}

	return nil
}

// Stats returns usage statistics including connected clients and relay metrics for all relays with differentiated keys
func Stats(ctx context.Context) (nip86.Response, error) {
	reject, authed := RejectAPICall(ctx)
	if reject {
		slog.Warn("unauthorized attempt to fetch stats", "caller", authed.Hex())
		return nip86.Response{}, errors.New("unauthorized: only the relay owner can fetch stats")
	}

	slog.Debug("fetching aggregated stats for all relays via NIP-86")

	relays := map[string]*khatru.Relay{
		"private": privateRelay,
		"chat":    chatRelay,
		"inbox":   inboxRelay,
		"outbox":  outboxRelay,
	}

	dbs := map[string]DBBackend{
		"private": privateDB,
		"chat":    chatDB,
		"inbox":   inboxDB,
		"outbox":  outboxDB,
	}

	statsData := map[string]interface{}{
		"whitelisted_count": len(config.WhitelistedPubKeys),
		"blacklisted_count": len(config.BlacklistedPubKeys),
	}

	for name, relay := range relays {
		var clientsCount, listenersCount int
		if relay != nil {
			clientsCount, listenersCount = relay.Stats()
		}

		var totalEvents uint32
		if db, exists := dbs[name]; exists && db != nil {
			totalEvents, _ = db.CountEvents(nostr.Filter{})
		}

		statsData[name+"_connected_clients"] = clientsCount
		statsData[name+"_active_listeners"] = listenersCount
		statsData[name+"_total_events"] = totalEvents
	}

	return nip86.Response{Result: statsData}, nil
}

// savePubKeysToFile helper function to dump map keys into a JSON array file as npubs
func savePubKeysToFile(filePath string, pubKeysMap map[string]struct{}) {
	npubs := []string{}
	for hexKey := range pubKeysMap {
		npub, err := pubkeyToNpub(hexKey)
		if err != nil {
			slog.Error("failed to encode pubkey to npub during persistence", "hex", hexKey, "error", err)
			continue
		}
		npubs = append(npubs, npub)
	}

	fileData, err := json.MarshalIndent(npubs, "", "  ")
	if err != nil {
		slog.Error("failed to marshal pubkeys for persistence", "file", filePath, "error", err)
		return
	}

	if err := os.WriteFile(filePath, fileData, 0644); err != nil {
		slog.Error("failed to write pubkeys file for persistence", "file", filePath, "error", err)
	}
}

// updateEnvFileString updates or adds a key-value string pair in the specified .env file safely, preserving comments and format
func updateEnvFileString(filePath string, key string, value string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		slog.Error("failed to read .env file for updating", "file", filePath, "error", err)
		return
	}

	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	updated := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Ignore comments and empty lines
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		// Split the line into key-value and comment parts
		parts := strings.SplitN(line, "#", 2)
		keyValuePart := strings.TrimSpace(parts[0])

		// Split the key-value part into key and value
		kv := strings.SplitN(keyValuePart, "=", 2)
		if len(kv) == 2 {
			currentKey := strings.TrimSpace(kv[0])
			if currentKey == key {
				// Preserve the comment if it exists
				commentPart := ""
				if len(parts) == 2 {
					commentPart = " #" + parts[1]
				}
				lines[i] = key + `="` + value + `"` + commentPart
				updated = true
				break
			}
		}
	}

	if !updated {
		// Remove trailing empty lines before appending the new key-value pair 
		for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}
		lines = append(lines, key+`="`+value+`"`, "")
	}

	output := strings.Join(lines, "\n")
	if err := os.WriteFile(filePath, []byte(output), 0644); err != nil {
		slog.Error("failed to write updated .env file", "file", filePath, "error", err)
	}
}