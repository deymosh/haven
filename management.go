package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip86"
	"fiatjaf.com/nostr/khatru"
)

func SetupManagementAPI(relay *khatru.Relay) {
	relay.ManagementAPI.AllowPubKey = AllowPubKey
	relay.ManagementAPI.UnallowPubKey = UnallowPubKey
	relay.ManagementAPI.ListAllowedPubKeys = ListAllowedPubKeys

	relay.ManagementAPI.BanPubKey = BanPubKey
	relay.ManagementAPI.UnbanPubKey = UnbanPubKey
	relay.ManagementAPI.ListBannedPubKeys = ListBannedPubKeys
}

// AllowPubKey adds a public key to the whitelist and persists it to the file
func AllowPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
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
	var banned []nip86.PubKeyReason
	for pubkey := range config.BlacklistedPubKeys {
		banned = append(banned, nip86.PubKeyReason{
			PubKey: nostr.MustPubKeyFromHex(pubkey),
			Reason: "blacklisted",
		})
	}

	return banned, nil
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