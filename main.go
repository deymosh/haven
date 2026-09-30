package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"github.com/spf13/afero"
	"golang.org/x/net/proxy"

	"github.com/barrydeen/haven/pkg/wot"
)

var (
	pool   *nostr.Pool
	config = loadConfig()
	fs     afero.Fs
)

// testTorConnectivity verifies that the Tor proxy is working by checking against Tor Project's official service.
// It relies on the process-wide http.DefaultTransport already being configured.
func testTorConnectivity() {
	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   http.DefaultClient.Timeout,
	}

	// Use the official Tor Project API to verify we're connected through Tor
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		log.Println("⚠️ Debug: Could not verify Tor connectivity:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Println("⚠️ Debug: Could not parse Tor check response:", err)
		return
	}

	// Check if the response indicates we're using Tor
	isTor, ok := result["IsTor"].(bool)
	if !ok {
		log.Println("⚠️ Debug: Could not determine Tor status from response")
		return
	}

	if isTor {
		log.Println("✅ Successfully verified - traffic is routing through Tor network!")
		if ip, ok := result["IP"].(string); ok {
			log.Printf("🧅 Tor exit node IP: %s\n", ip)
		}
	} else {
		log.Println("⚠️ Debug: ❌ WARNING - traffic is NOT routing through Tor")
		if ip, ok := result["IP"].(string); ok {
			log.Printf("⚠️ Debug: Current IP: %s\n", ip)
		}
	}
}

// createPoolWithProxy creates a nostr relay pool with optional SOCKS5 proxy support.
// If PROXY_URL environment variable is set, all outgoing connections will route through the proxy.
// This is useful for privacy-preserving setups using Tor.
func createPoolWithProxy(ctx context.Context) *nostr.Pool {
	if config.ProxyURL != "" {
		log.Println("🔒 Proxy configured - routing ALL connections through SOCKS5:", config.ProxyURL)

		// Create a dialer that uses SOCKS5 for connection routing
		dialer, err := proxy.SOCKS5("tcp", config.ProxyURL, nil, &net.Dialer{})
		if err != nil {
			log.Fatalf("failed to create SOCKS5 dialer: %s", err)
		}

		// Create custom transport with SOCKS5 dialer
		transport := &http.Transport{
			Dial: dialer.Dial,
		}

		// Set as default transport for all http clients in the program
		// This ensures ALL outgoing HTTP/HTTPS connections use the proxy
		http.DefaultTransport = transport

		log.Println("✅ SOCKS5 proxy initialized - all outgoing connections will route through proxy")

		// Debug: test Tor connectivity using the process-wide default transport.
		testTorConnectivity()
	} else {
		// Default pool without proxy
		log.Println("No proxy configured - connections will use direct IP")
	}

	newPool := nostr.NewPool()
	newPool.Context = ctx
	newPool.RelayOptions = nostr.RelayOptions{
		RequestHeader: http.Header{
			"User-Agent": []string{config.UserAgent},
		},
	}
	newPool.StartPenaltyBox()

	return newPool
}

func main() {
	nostr.InfoLogger = log.New(io.Discard, "", 0)
	slog.SetLogLoggerLevel(getLogLevelFromConfig())
	green := "\033[32m"
	reset := "\033[0m"
	fmt.Println(green + art + reset)

	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs = afero.NewOsFs()
	if err := fs.MkdirAll(config.BlossomPath, 0755); err != nil {
		log.Fatal("🚫 error creating blossom path:", err)
	}
	checkBlobPath()

	// before the subcommand switch below, so backup, restore and import get the
	// same view of who is banned and allowed as the relay does
	loadManagementStore()

	pool = createPoolWithProxy(mainCtx)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "backup":
			runBackup(mainCtx)
			return
		case "restore":
			runRestore(mainCtx)
			return
		case "import":
			ensureImportRelays()
			runImport(mainCtx)
			return
		case "help":
			printHelp()
			return
		}

		if os.Args[1] == "-h" || os.Args[1] == "--help" {
			printHelp()
			return
		}
	}

	flag.Parse()

	log.Println("🚀 HAVEN", config.RelayVersion, "is booting up")
	defer log.Println("🔌 HAVEN is shutting down")
	log.Println("👥 Number of whitelisted pubkeys:", len(whitelistedPubKeySet()))
	log.Println("🚷 Number of blacklisted pubkeys:", len(config.BlacklistedPubKeys))

	ensureImportRelays()
	wotModel := wot.NewSimpleInMemory(
		pool,
		whitelistedPubKeySet,
		config.ImportSeedRelays,
		config.WotDepth,
		config.WotMinimumFollowers,
		config.WotFetchTimeoutSeconds,
	)
	wot.Initialize(mainCtx, wotModel)
	initRelays(mainCtx)

	// after initRelays, because instrument() is what creates the per relay
	// counters this reads a history into, and before the goroutines below so the
	// first fold has something to fold onto
	loadMetricsStore()

	go func() {
		go subscribeInboxAndChat(mainCtx)
		go startPeriodicCloudBackups(mainCtx)
		go wot.PeriodicRefresh(mainCtx, config.WotRefreshInterval)
		go runMetrics(mainCtx)
		go runAggregates(mainCtx)
	}()

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("templates/static"))))
	http.HandleFunc("/admin", adminHandler)
	// without this "/admin/" would fall through to the catch-all below, reach
	// the outbox relay and come back as a bare 404
	http.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusMovedPermanently)
	})
	http.HandleFunc("/", dynamicRelayHandler)

	addr := fmt.Sprintf("%s:%d", config.RelayBindAddress, config.RelayPort)

	log.Printf("🔗 listening at %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal("🚫 error starting server:", err)
	}
}

func printHelp() {
	fmt.Println("haven is a personal nostr relay.")
	fmt.Println()
	fmt.Println("usage: haven [command]")
	fmt.Println()
	fmt.Println("commands:")
	fmt.Println("  backup  - backup the database")
	fmt.Println("  restore - restore the database")
	fmt.Println("  import  - import notes from seed relays")
	fmt.Println("  help    - show this help message")
	fmt.Println()
	fmt.Println("if no command is provided, the relay starts by default.")
	fmt.Println()
	fmt.Println("run 'haven [command] --help' for more information on a command.")
}

func dynamicRelayHandler(w http.ResponseWriter, r *http.Request) {
	relay, relayName, exact := relayForPath(r.URL.Path)

	// NIP-86 is answered by haven rather than by khatru: khatru's handler
	// reports auth failures as HTTP 200 where the NIP asks for a 401, does not
	// check the auth event's kind or method tag, and has no way to serve the
	// console's own methods (its Generic fallback is unreachable, because
	// nip86.DecodeRequest rejects any method it does not know)
	if isNIP86Request(r) {
		handleManagementRequest(w, r, relay, relayName, exact)
		return
	}

	relay.ServeHTTP(w, r)
}

// relayForPath maps a request path onto one of the four relays. exact reports
// whether the path names that relay outright: everything unmatched lands on the
// outbox relay, which also serves blossom, so a caller that needs to know it is
// really addressing a relay — NIP-86 does, it lives on the relay's own URI and
// nowhere else — has to ask.
func relayForPath(path string) (*khatru.Relay, string, bool) {
	// trailing slashes used to fall through to the outbox relay, so "/private/"
	// silently served the wrong one
	switch strings.TrimSuffix(path, "/") {
	case "/private":
		return privateRelay, relayPrivate, true
	case "/chat":
		return chatRelay, relayChat, true
	case "/inbox":
		return inboxRelay, relayInbox, true
	case "":
		return outboxRelay, relayOutbox, true
	default:
		return outboxRelay, relayOutbox, false
	}
}

func getLogLevelFromConfig() slog.Level {
	switch config.LogLevel {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo // Default level
	}
}
