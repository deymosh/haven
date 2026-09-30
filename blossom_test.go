package main

import (
	"context"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru/blossom"
	nipb7blossom "fiatjaf.com/nostr/nipb7/blossom"
	"github.com/spf13/afero"
)

// TestDeleteBlobsRemovesEveryUploadersEntryAndNothingElse: deleteBlobs finds its
// entries through the x tag index rather than a walk of the whole kind, so it has
// to prove it still reaches every uploader's claim on a hash, across more than
// one page, and leaves the other blobs alone.
func TestDeleteBlobsRemovesEveryUploadersEntryAndNothingElse(t *testing.T) {
	db := newTestDB(t, 2)
	originalDB, originalFs, originalPath := blossomDB, fs, config.BlossomPath
	blossomDB, fs, config.BlossomPath = db, afero.NewMemMapFs(), "blossom/"
	t.Cleanup(func() { blossomDB, fs, config.BlossomPath = originalDB, originalFs, originalPath })

	doomed := "aa" + nostr.Generate().Public().Hex()[2:]
	kept := "bb" + nostr.Generate().Public().Hex()[2:]

	index := blossom.EventStoreBlobIndexWrapper{Store: db}
	for i := range 5 {
		uploader := nostr.Generate().Public()
		for _, hash := range []string{doomed, kept} {
			blob := nipb7blossom.BlobDescriptor{SHA256: hash, Type: "image/png", Size: 3, Uploaded: nostr.Timestamp(1700000000 + i)}
			if err := index.Keep(context.Background(), blob, uploader); err != nil {
				t.Fatalf("keep: %v", err)
			}
		}
	}
	for _, hash := range []string{doomed, kept} {
		if err := writeBlob(hash, []byte("png")); err != nil {
			t.Fatalf("write blob: %v", err)
		}
	}

	results, err := deleteBlobs(context.Background(), []string{doomed}, false, "")
	if err != nil {
		t.Fatalf("deleteBlobs: %v", err)
	}
	if len(results) != 1 || results[0].IndexRemoved != 5 || !results[0].FileRemoved || results[0].Error != "" {
		t.Fatalf("result = %+v, want 5 index entries and the file removed", results)
	}

	remaining := map[string]int{}
	for evt := range db.QueryEvents(nostr.Filter{Kinds: []nostr.Kind{blobIndexKind}}, 100) {
		parsed, _ := parseBlobIndexEvent(evt)
		remaining[parsed.SHA256]++
	}
	if remaining[doomed] != 0 || remaining[kept] != 5 {
		t.Errorf("index after delete = %v, want only the 5 entries for the kept blob", remaining)
	}
	if ok, _ := afero.Exists(fs, blobPath(kept)); !ok {
		t.Error("the kept blob's file was removed")
	}
}
