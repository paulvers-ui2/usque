// Package chain nests tunnels inside one process:
//
//	apps -> SOCKS -> WARP2 (exit) -> wg0 -> WARP1 -> host network
//
// WARP1 hides the user from the ISP, wg0 gives a new location and WARP2
// "washes" the wg0 server IP into a Cloudflare egress IP. Every hop is a
// userspace network stack; each hop dials its transport through the stack
// of the hop below it, so nothing touches the host routing table.
package chain

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/doh"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	// wgOverhead4/6: WireGuard data header+tag (32) + UDP (8) + IP header.
	wgOverhead4 = 32 + 8 + 20
	wgOverhead6 = 32 + 8 + 40
)

// WarpHop configures one MASQUE hop.
type WarpHop struct {
	Name              string
	Config            *config.Config
	SNI               string
	UseHTTP2          bool
	UseIPv6           bool
	ConnectPort       int
	InitialPacketSize uint16
	MTU               int
	Keepalive         time.Duration
	ReconnectDelay    time.Duration
	AlwaysReconnect   bool
	Insecure          bool
	// FallbackHTTP2After switches an HTTP/3 hop to HTTP/2 after that many failed
	// connects in a row (0 = never). Meant for WARP1, the only hop on the host
	// network, where UDP 443 may be dropped or throttled.
	FallbackHTTP2After int

	// IdleTimeout, ConnectTimeout, WatchPath and StallTimeout: see
	// api.MaintainTunnelConfig. WatchPath only applies to a hop on the host
	// network. The stall probe connects to ProbeAddr through this hop.
	IdleTimeout    time.Duration
	ConnectTimeout time.Duration
	WatchPath      bool
	StallTimeout   time.Duration
	ProbeAddr      string
	// Health is kept up to date for the hop above; UnderlayHealthy is the hop
	// below's, so this hop does not rebuild itself for an outage down there.
	Health          *api.Health
	UnderlayHealthy func() bool
	// Connected runs after every successful connect of this hop.
	Connected func()
}

// UnderlayOf makes a tunnel's stack usable as the transport of the next hop.
func UnderlayOf(n *netstack.Net) *api.Underlay {
	if n == nil {
		return nil
	}
	return &api.Underlay{
		ListenPacket: func(endpoint *net.UDPAddr) (net.PacketConn, error) {
			ap, ok := netip.AddrFromSlice(endpoint.IP)
			if !ok {
				return nil, fmt.Errorf("chain: bad endpoint %v", endpoint)
			}
			// netstack only routes *connected* UDP, so dial the endpoint and
			// wrap the conn so quic-go's WriteTo(addr) always targets it.
			uc, err := n.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(ap.Unmap(), uint16(endpoint.Port)))
			if err != nil {
				return nil, err
			}
			return &fixedDestPacketConn{UDPConn: uc, remote: endpoint}, nil
		},
		DialContext: n.DialContext,
	}
}

// fixedDestPacketConn wraps a connected netstack UDP conn as a net.PacketConn
// whose sends always go to the dialed remote (ignoring the addr quic-go passes)
// and whose receives report that remote as the source.
type fixedDestPacketConn struct {
	*gonet.UDPConn
	remote *net.UDPAddr
}

func (c *fixedDestPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }
func (c *fixedDestPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.remote, err
}
func (c *fixedDestPacketConn) LocalAddr() net.Addr { return c.UDPConn.LocalAddr() }

// StartWarp brings up a MASQUE hop over under (nil = host network) and returns
// the userspace stack that dials through it.
func StartWarp(ctx context.Context, h WarpHop, under *netstack.Net) (*netstack.Net, error) {
	c := h.Config
	privKey, err := c.GetEcPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	peerPub, err := c.GetEcEndpointPublicKey()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPub, cert, h.SNI, h.Insecure)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	return startWarpTLS(ctx, h, tlsConfig, under)
}

func startWarpTLS(ctx context.Context, h WarpHop, tlsConfig *tls.Config, under *netstack.Net) (*netstack.Net, error) {
	c := h.Config
	endpoint, err := c.SelectEndpoint(h.UseHTTP2, h.UseIPv6, h.ConnectPort)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	var addrs []netip.Addr
	for _, s := range []string{c.IPv4, c.IPv6} {
		if a, err := netip.ParseAddr(s); err == nil {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: config has no tunnel addresses", h.Name)
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, nil, h.MTU)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	transport := "HTTP/3"
	if h.UseHTTP2 {
		transport = "HTTP/2"
	}
	var fallback net.Addr
	if !h.UseHTTP2 && h.FallbackHTTP2After > 0 {
		if fallback, err = c.SelectEndpoint(true, h.UseIPv6, h.ConnectPort); err != nil {
			return nil, fmt.Errorf("%s: HTTP/2 fallback endpoint: %w", h.Name, err)
		}
		transport = fmt.Sprintf("HTTP/3 (HTTP/2 after %d failed connects)", h.FallbackHTTP2After)
	}
	log.Printf("chain: %s up: %s via %s, tunnel MTU %d", h.Name, endpoint, transport, h.MTU)
	var probe func(context.Context) error
	if h.StallTimeout > 0 && h.ProbeAddr != "" {
		probe = api.TCPProbe(tnet.DialContext, h.ProbeAddr)
	}
	go api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
		TLSConfig:         tlsConfig,
		KeepalivePeriod:   h.Keepalive,
		InitialPacketSize: h.InitialPacketSize,
		Endpoint:          endpoint,
		Device:            api.NewNetstackAdapter(tunDev),
		MTU:               h.MTU,
		ReconnectDelay:    h.ReconnectDelay,
		AlwaysReconnect:   h.AlwaysReconnect,
		UseHTTP2:          h.UseHTTP2,
		Underlay:          UnderlayOf(under),

		FallbackHTTP2Endpoint: fallback,
		FallbackHTTP2After:    h.FallbackHTTP2After,

		IdleTimeout:     h.IdleTimeout,
		ConnectTimeout:  h.ConnectTimeout,
		WatchPath:       h.WatchPath && under == nil,
		Probe:           probe,
		StallTimeout:    h.StallTimeout,
		UnderlayHealthy: h.UnderlayHealthy,
		Health:          h.Health,
		Connected:       h.Connected,
	})
	go func() { <-ctx.Done(); _ = tunDev.Close() }()
	return tnet, nil
}

// WGHop configures the WireGuard hop.
type WGHop struct {
	Config *WGConfig
	// UnderMTU is the MTU of the stack wg0 rides on (WARP1's tunnel MTU).
	UnderMTU int
	// Keepalive is used when the config does not set PersistentKeepalive.
	Keepalive int
	// MTU, when > 0, replaces the config's MTU (still capped to what fits
	// inside the hop below).
	MTU int
	// Resolver resolves a hostname Endpoint; it should dial through the hop
	// below so the lookup is not visible to the ISP.
	Resolver *doh.Client
	LogLevel int
}

// WGMTU is the largest inner MTU that keeps wg0 packets inside the hop below.
func WGMTU(underMTU int, endpointV6 bool, configured int) int {
	over := wgOverhead4
	if endpointV6 {
		over = wgOverhead6
	}
	m := underMTU - over
	if configured > 0 && configured < m {
		m = configured
	}
	return m
}

func resolveEndpoint(ctx context.Context, host string, r *doh.Client) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	if r == nil {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return netip.Addr{}, fmt.Errorf("resolve %s: %v", host, err)
		}
		return pickV4(ips), nil
	}
	ips, err := r.LookupIP(ctx, host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s through WARP1: %v", host, err)
	}
	var out []netip.Addr
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return pickV4(out), nil
}

// pickV4 prefers IPv4: its smaller header leaves 20 more bytes of MTU.
func pickV4(ips []netip.Addr) netip.Addr {
	for _, a := range ips {
		if a.Unmap().Is4() {
			return a.Unmap()
		}
	}
	return ips[0]
}

// WGStack is a running wg0 hop.
type WGStack struct {
	// Net dials through wg0.
	Net *netstack.Net
	// MTU is the inner MTU chosen for wg0.
	MTU int
	dev *device.Device
}

// Nudge sends a keepalive to the peer now, if a session is current. Call it
// after the hop below reconnects: WARP1 may come back with a new egress IP, and
// the wg0 server only learns it from the next packet the client sends.
func (w *WGStack) Nudge() { w.dev.SendKeepalivesToPeersWithCurrentKeypair() }

const (
	// endpointRetry spaces out lookups of a hostname Endpoint that has not
	// resolved yet (WARP1 may still be connecting).
	endpointRetry = 2 * time.Second
	// endpointRecheck is how often a resolved hostname Endpoint is looked at
	// again; it is only re-resolved when wg0 has had no handshake for
	// endpointStale (the server may have moved, as with dynamic DNS).
	endpointRecheck = time.Minute
	endpointStale   = 3 * time.Minute
)

// StartWG brings up wg0 with its UDP carried inside under. A hostname Endpoint
// is resolved in the background through the hop below, retried until it works
// and re-resolved when the handshakes stop, so the chain starts (and the SOCKS
// port opens) even while WARP1 is still connecting.
func StartWG(ctx context.Context, h WGHop, under *netstack.Net) (*WGStack, error) {
	cfg := h.Config
	host, port, err := SplitEndpoint(cfg.Peers[0].Endpoint)
	if err != nil {
		return nil, err
	}
	var ep netip.AddrPort
	if a, perr := netip.ParseAddr(host); perr == nil {
		ep = netip.AddrPortFrom(a.Unmap(), port)
	}

	want := cfg.MTU
	if h.MTU > 0 {
		want = h.MTU
	}
	// A hostname counts as IPv4 until resolved: pickV4 prefers IPv4.
	endpointV6 := ep.IsValid() && ep.Addr().Is6()
	mtu := WGMTU(h.UnderMTU, endpointV6, want)
	if want > mtu {
		log.Printf("chain: wg0 MTU %d does not fit inside WARP1 (%d); using %d", want, h.UnderMTU, mtu)
	}
	var addrs []netip.Addr
	for _, p := range cfg.Addresses {
		a := p.Addr()
		if a.Is6() && mtu < 1280 {
			// IPv6 needs a 1280-byte link; the exit hop uses IPv4 anyway.
			log.Printf("chain: wg0 MTU %d < 1280, ignoring IPv6 address %s", mtu, a)
			continue
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("wg0: no usable IPv4 Address at MTU %d", mtu)
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, cfg.DNS, mtu)
	if err != nil {
		return nil, fmt.Errorf("wg0: %w", err)
	}
	keepalive := cfg.Peers[0].PersistentKeepalive
	if keepalive <= 0 {
		keepalive = h.Keepalive
	}
	dev := device.NewDevice(tunDev, newNetstackBind(under), device.NewLogger(h.LogLevel, "wg0: "))
	if err := dev.IpcSet(cfg.UAPI(ep, keepalive)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg0: config rejected: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg0: %w", err)
	}
	peer := cfg.Peers[0].Endpoint
	if ep.IsValid() {
		peer = ep.String()
	}
	log.Printf("chain: wg0 started: peer %s, inner MTU %d, keepalive %ds (waiting for handshake)", peer, mtu, keepalive)
	go func() { <-ctx.Done(); dev.Close() }()
	go watchHandshake(ctx, dev, peer)
	if !ep.IsValid() {
		go followEndpoint(ctx, dev, cfg, host, port, h.Resolver)
	}
	return &WGStack{Net: tnet, MTU: mtu, dev: dev}, nil
}

// followEndpoint keeps wg0's peer pointed at what host resolves to: first
// until the lookup works, then again whenever the handshakes stop.
func followEndpoint(ctx context.Context, dev *device.Device, cfg *WGConfig, host string, port uint16, r *doh.Client) {
	var cur netip.AddrPort
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		next := endpointRecheck
		if !cur.IsValid() || handshakeOlderThan(dev, endpointStale) {
			rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			addr, err := resolveEndpoint(rctx, host, r)
			cancel()
			switch {
			case err != nil:
				log.Printf("chain: wg0: %v (retrying)", err)
				if !cur.IsValid() {
					next = endpointRetry
				}
			case netip.AddrPortFrom(addr, port) != cur:
				ep := netip.AddrPortFrom(addr, port)
				if err := dev.IpcSet(cfg.EndpointUAPI(ep)); err != nil {
					log.Printf("chain: wg0: setting endpoint %s: %v", ep, err)
					next = endpointRetry
					break
				}
				log.Printf("chain: wg0 endpoint %s -> %s", host, ep)
				if addr.Is6() {
					log.Printf("chain: WARNING: wg0 endpoint %s is IPv6 but wg0's MTU was sized for IPv4; lower --wg-mtu by 20 if large packets stall", host)
				}
				cur = ep
			}
		}
		t.Reset(next)
	}
}

// handshakeOlderThan reports whether wg0's last handshake is older than d (or
// there was none yet).
func handshakeOlderThan(dev *device.Device, d time.Duration) bool {
	s, err := dev.IpcGet()
	if err != nil {
		return false
	}
	last := lastHandshake(s)
	return last.IsZero() || time.Since(last) > d
}

// lastHandshake reads last_handshake_time_sec from wireguard-go's IpcGet output.
func lastHandshake(uapi string) time.Time {
	for _, line := range strings.Split(uapi, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			if sec, err := strconv.ParseInt(v, 10, 64); err == nil && sec > 0 {
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}

// watchHandshake logs when wg0 really comes up: dev.Up only starts the
// device, the peer is reachable once a handshake completes.
func watchHandshake(ctx context.Context, dev *device.Device, peer string) {
	start := time.Now()
	warned := false
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s, err := dev.IpcGet(); err == nil && hasHandshake(s) {
			log.Printf("chain: wg0 up: handshake with %s after %s", peer, time.Since(start).Round(time.Millisecond))
			return
		}
		if !warned && time.Since(start) > 15*time.Second {
			log.Printf("chain: WARNING: wg0 has no handshake with %s after 15s (check the keys and endpoint, or the server may drop Cloudflare IPs)", peer)
			warned = true
		}
	}
}

func hasHandshake(uapi string) bool {
	for _, line := range strings.Split(uapi, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok && v != "0" {
			return true
		}
	}
	return false
}

// ExitTransportFits reports whether the exit hop can run QUIC through wg0.
// QUIC needs 1200-byte UDP payloads both ways, and Cloudflare may send up to
// 1452, which a wg0 inside WARP1 (MTU ~1220) cannot carry.
func ExitTransportFits(wgMTU int) bool {
	return wgMTU-28 >= 1452
}
