package cmd

import (
	"net/netip"
	"time"

	"github.com/spf13/cobra"
)

// Probe targets for the stall check: Cloudflare's resolver, which answers on 443
// from inside every WARP tunnel.
const (
	probeAddrV4 = "1.1.1.1:443"
	probeAddrV6 = "[2606:4700:4700::1111]:443"
)

// resilience holds the flags that decide how fast a dead tunnel is noticed and
// rebuilt (see api/health.go).
type resilience struct {
	idleTimeout    time.Duration
	connectTimeout time.Duration
	watchNetwork   bool
	stallTimeout   time.Duration
	probeAddr      string
}

func addResilienceFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.Duration("idle-timeout", 0, "QUIC idle timeout: a connection that hears nothing for this long is rebuilt (0 = QUIC default, 30s)")
	f.Duration("connect-timeout", 15*time.Second, "Give up on one connect attempt after this long (0 = no limit)")
	f.Bool("watch-network", true, "Reconnect at once when the local network changes (Wi-Fi <-> mobile data) or comes back after an outage")
	f.Duration("stall-timeout", 3*time.Second, "Reconnect when packets go out but nothing comes back for this long and a TCP probe through the tunnel gets no answer either (0 = off)")
	f.String("probe-addr", "", "host:port the stall probe connects to through the tunnel (default "+probeAddrV4+", or "+probeAddrV6+" without tunnel IPv4)")
}

func readResilienceFlags(cmd *cobra.Command) resilience {
	f := cmd.Flags()
	var r resilience
	r.idleTimeout, _ = f.GetDuration("idle-timeout")
	r.connectTimeout, _ = f.GetDuration("connect-timeout")
	r.watchNetwork, _ = f.GetBool("watch-network")
	r.stallTimeout, _ = f.GetDuration("stall-timeout")
	r.probeAddr, _ = f.GetString("probe-addr")
	return r
}

// probeTarget picks the probe address: the flag if set, else Cloudflare's
// resolver in a family the tunnel carries.
func (r resilience) probeTarget(tunnelAddrs []netip.Addr) string {
	if r.probeAddr != "" {
		return r.probeAddr
	}
	for _, a := range tunnelAddrs {
		if a.Unmap().Is4() {
			return probeAddrV4
		}
	}
	if len(tunnelAddrs) > 0 {
		return probeAddrV6
	}
	return probeAddrV4
}
