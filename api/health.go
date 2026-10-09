package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// A tunnel can die without either side saying so: the phone moves from Wi-Fi to
// mobile data and the QUIC socket keeps sending from an address that no longer
// exists, or a middlebox drops the flow. QUIC only notices after its idle timeout
// (30s by default), so MaintainTunnel watches for two cheaper signals and drops
// the connection itself, then reconnects at once:
//
//   - the network path changed: the local address the OS would use to reach the
//     endpoint is different (or the network just came back after an outage);
//   - the tunnel stalled: packets went out but nothing came back for a while, and
//     a TCP probe through the tunnel got no answer either.

var (
	// errPathChanged and errStalled end a connection that is (almost certainly)
	// dead; MaintainTunnel reconnects without waiting ReconnectDelay.
	errPathChanged = errors.New("network path changed")
	errStalled     = errors.New("tunnel stalled")
)

const (
	// healthTick is how often the per-connection watcher checks the path and the
	// stall clock. Also the worst-case delay before a path change is noticed.
	healthTick = time.Second
	// minProbeTimeout bounds a liveness probe from below; a probe through the
	// tunnel costs one round trip, which can be a second or more on mobile data.
	minProbeTimeout = 2500 * time.Millisecond
	// healthyStallGrace is how long an unanswered packet may wait before Healthy
	// stops vouching for the tunnel (used by the hop above to hold off its own
	// probes while this one recovers).
	healthyStallGrace = 2 * time.Second
)

// monoBase anchors monoNow; time.Since reads the monotonic clock, so wall-clock
// jumps (NTP, the user changing the time) cannot fake or hide a stall.
var monoBase = time.Now()

// monoNow returns monotonic nanoseconds since monoBase, never 0.
func monoNow() int64 { return int64(time.Since(monoBase)) + 1 }

// Health is a live view of one MaintainTunnel loop. It can be shared with the hop
// riding on top of this tunnel (see MaintainTunnelConfig.UnderlayHealthy) so that
// hop does not tear itself down for an outage that is really down here.
type Health struct {
	connected atomic.Bool
	// pending is the monoNow time of the first packet sent since the last one was
	// received, or 0 when nothing sent is waiting for an answer.
	pending atomic.Int64
}

// sent records an outbound packet.
func (h *Health) sent() { h.pending.CompareAndSwap(0, monoNow()) }

// received records an inbound packet. Load first: this runs per packet and a
// plain load keeps the cache line shared while nothing is pending.
func (h *Health) received() {
	if h.pending.Load() != 0 {
		h.pending.Store(0)
	}
}

// unansweredFor is how long the oldest unanswered packet has been waiting.
func (h *Health) unansweredFor() time.Duration {
	p := h.pending.Load()
	if p == 0 {
		return 0
	}
	return time.Duration(monoNow() - p)
}

func (h *Health) setConnected(up bool) {
	h.connected.Store(up)
	h.pending.Store(0)
}

// Connected reports whether the tunnel currently has a live MASQUE connection.
func (h *Health) Connected() bool { return h != nil && h.connected.Load() }

// Healthy reports whether the tunnel is connected and nothing it sent has gone
// unanswered for more than a couple of seconds.
func (h *Health) Healthy() bool {
	return h.Connected() && h.unansweredFor() <= healthyStallGrace
}

// TCPProbe returns a liveness probe that opens, and at once closes, a TCP
// connection to addr through dial. Only silence counts as failure: a refused
// connection still proves packets flow both ways, and an immediate local error
// (say, no route for that address family) says nothing about the tunnel.
func TCPProbe(dial func(ctx context.Context, network, address string) (net.Conn, error), addr string) func(context.Context) error {
	return func(ctx context.Context) error {
		c, err := dial(ctx, "tcp", addr)
		if err == nil {
			_ = c.Close()
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("no answer from %s", addr)
		}
		return nil
	}
}

// RouteLocalAddr returns a path identifier for reaching endpoint over the host
// network: the local address the OS would send from. Connecting a UDP socket
// only looks up the route, so no packet leaves the machine.
func RouteLocalAddr(endpoint net.Addr) func() (string, error) {
	var dst *net.UDPAddr
	switch a := endpoint.(type) {
	case *net.UDPAddr:
		dst = &net.UDPAddr{IP: a.IP, Port: a.Port}
	case *net.TCPAddr:
		dst = &net.UDPAddr{IP: a.IP, Port: a.Port}
	}
	return func() (string, error) {
		if dst == nil {
			return "", fmt.Errorf("no route check for %T", endpoint)
		}
		c, err := net.DialUDP("udp", nil, dst)
		if err != nil {
			return "", err
		}
		defer func() { _ = c.Close() }()
		la, ok := c.LocalAddr().(*net.UDPAddr)
		if !ok {
			return "", fmt.Errorf("unexpected local address %v", c.LocalAddr())
		}
		return la.IP.String(), nil
	}
}

// pathWatch compares the current path against the one a connection was made on.
type pathWatch struct {
	id   func() (string, error)
	base string
	lost bool // the network was unreachable at some check since the connect
}

func newPathWatch(id func() (string, error)) *pathWatch {
	p := &pathWatch{id: id}
	base, err := id()
	p.base, p.lost = base, err != nil
	return p
}

// check returns why the connection's path is gone, or "" while it still holds.
// An unreachable network is not a reason by itself (there is nothing to
// reconnect over yet); its return is.
func (p *pathWatch) check() string {
	cur, err := p.id()
	switch {
	case err != nil:
		if !p.lost {
			log.Printf("Network unreachable (%v); reconnecting as soon as it is back", err)
			p.lost = true
		}
		return ""
	case p.lost:
		return fmt.Sprintf("network is back (local address %s)", cur)
	case cur != p.base:
		return fmt.Sprintf("local address %s -> %s", p.base, cur)
	}
	return ""
}

// probeTimeout gives a probe at least minProbeTimeout, or the stall timeout when
// that is longer.
func probeTimeout(stall time.Duration) time.Duration {
	return max(stall, minProbeTimeout)
}

// watchHealth runs for the life of one connection and reports on lost when the
// connection should be dropped. path may be nil (no path check), as may probe.
func watchHealth(ctx context.Context, h *Health, path *pathWatch, probe func(context.Context) error,
	stall time.Duration, underlayHealthy func() bool, lost chan<- error) {
	t := time.NewTicker(healthTick)
	defer t.Stop()
	var lastProbe time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if path != nil {
			if why := path.check(); why != "" {
				lost <- fmt.Errorf("%w: %s", errPathChanged, why)
				return
			}
		}
		if probe == nil || stall <= 0 {
			continue
		}
		waiting := h.unansweredFor()
		if waiting < stall || time.Since(lastProbe) < stall {
			continue
		}
		if underlayHealthy != nil && !underlayHealthy() {
			// The tunnel underneath is itself down or recovering; tearing this one
			// down too would only add a reconnect on top of its recovery.
			continue
		}
		lastProbe = time.Now()
		pctx, cancel := context.WithTimeout(ctx, probeTimeout(stall))
		err := probe(pctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			lost <- fmt.Errorf("%w: nothing received for %s and %v", errStalled, waiting.Round(100*time.Millisecond), err)
			return
		}
	}
}
