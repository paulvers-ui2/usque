package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The app (rethink-app-masque ChainArgs) starts the chain with these flags. A chain that
// does not know one of them exits with "unknown flag" before its SOCKS port opens, which
// took the app's chain down until the app was reinstalled.
var appChainArgs = []string{
	"-b", "127.0.0.1", "-p", "40001", "-c", "-", "--wg", "-", "--exit-config", "-",
	"-s", "google.com", "-m", "1280", "-i", "1350", "-P", "443", "-k", "10s", "-r", "1s",
	"--always-reconnect", "--idle-timeout", "25s", "--stall-timeout", "2s",
	"--doh", "--dnssec", "validate",
	"--doh-url", "https://1.1.1.1/dns-query", "--doh-url", "https://1.0.0.1/dns-query",
	"--wg-mtu", "0", "--wg-keepalive", "25",
	"--exit-sni", "amazon.com", "--exit-transport", "auto", "--exit-mtu", "1280",
	"--exit-connect-port", "443", "--exit-stall-timeout", "8s",
}

func freshChainCmd() *cobra.Command {
	c := &cobra.Command{Use: "chain"}
	// -c and --secrets-stdin are root persistent flags; the app passes -c.
	c.Flags().StringP("config", "c", "config.json", "config file")
	c.Flags().Bool("secrets-stdin", false, "keys from stdin")
	defineChainFlags(c)
	return c
}

func TestChainAcceptsAppFlags(t *testing.T) {
	c := freshChainCmd()
	if err := c.Flags().Parse(appChainArgs); err != nil {
		t.Fatalf("chain rejects the app's flags: %v", err)
	}
	f := c.Flags()
	if v, err := f.GetBool("always-reconnect"); err != nil || !v {
		t.Fatalf("--always-reconnect = %v, %v; want true", v, err)
	}
	if v, err := f.GetBool("doh"); err != nil || !v {
		t.Fatalf("--doh = %v, %v; want true", v, err)
	}
	if v, err := f.GetString("dnssec"); err != nil || v != "validate" {
		t.Fatalf("--dnssec = %q, %v; want validate", v, err)
	}
	urls, err := f.GetStringArray("doh-url")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(urls, ",") != "https://1.1.1.1/dns-query,https://1.0.0.1/dns-query" {
		t.Fatalf("--doh-url = %v; want only the two Cloudflare endpoints", urls)
	}
	// Left out by the app: usque's own default applies.
	if v, err := f.GetInt("http2-fallback-after"); err != nil || v != 2 {
		t.Fatalf("--http2-fallback-after default = %v, %v; want 2", v, err)
	}
}

func TestChainAlwaysReconnectDefaultsOnAndCanBeTurnedOff(t *testing.T) {
	fl := freshChainCmd().Flags().Lookup("always-reconnect")
	if fl == nil {
		t.Fatal("chain has no --always-reconnect flag")
	}
	if fl.DefValue != "true" {
		t.Fatalf("--always-reconnect defaults to %s; want true (the chain always reconnected)", fl.DefValue)
	}
	c := freshChainCmd()
	if err := c.Flags().Parse([]string{"--always-reconnect=false"}); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Flags().GetBool("always-reconnect"); err != nil || v {
		t.Fatalf("--always-reconnect=false gave %v, %v", v, err)
	}
}

func TestChainStillRejectsUnknownFlags(t *testing.T) {
	err := freshChainCmd().Flags().Parse([]string{"--no-such-flag"})
	if err == nil || !strings.Contains(err.Error(), "unknown flag: --no-such-flag") {
		t.Fatalf("unknown flag error = %v", err)
	}
}
