package simtest

// End-to-end checks that a tunnel which dies silently is rebuilt quickly. The
// fake edge here serves every client "path" from one QUIC server, and a path
// can be cut so its packets vanish without an error, like a phone leaving
// Wi-Fi: only usque's own health checks can notice.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// simNet connects any number of client sockets to one server socket. Each
// client socket is one network path; cut() makes every current path drop all
// its packets in both directions without telling anyone.
type simNet struct {
	mu      sync.Mutex
	toSrv   chan pkt
	clients map[string]*simClient
	next    int
	srvDone chan struct{}
}

func newSimNet() *simNet {
	return &simNet{toSrv: make(chan pkt, 1024), clients: map[string]*simClient{}, srvDone: make(chan struct{})}
}

type simClient struct {
	n      *simNet
	addr   udpAddr
	rx     chan pkt
	dead   atomic.Bool
	once   sync.Once
	closed chan struct{}
}

func (n *simNet) newClient() *simClient {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.next++
	c := &simClient{n: n, addr: udpAddr{"10.9.0." + strconv.Itoa(n.next) + ":40000"}, rx: make(chan pkt, 1024), closed: make(chan struct{})}
	n.clients[c.addr.String()] = c
	return c
}

// cut silently kills every path that exists now; new ones work.
func (n *simNet) cut() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.clients {
		c.dead.Store(true)
	}
}

func (c *simClient) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if c.dead.Load() {
		return len(p), nil
	}
	select {
	case c.n.toSrv <- pkt{b: append([]byte(nil), p...), addr: c.addr}:
	default:
	}
	return len(p), nil
}

func (c *simClient) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pk := <-c.rx:
		return copy(p, pk.b), pk.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *simClient) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *simClient) LocalAddr() net.Addr              { return c.addr }
func (c *simClient) SetDeadline(time.Time) error      { return nil }
func (c *simClient) SetReadDeadline(time.Time) error  { return nil }
func (c *simClient) SetWriteDeadline(time.Time) error { return nil }

// simServer is the edge's side of simNet.
type simServer struct{ n *simNet }

var edgeAddr = udpAddr{"10.0.0.1:443"}

func (s simServer) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pk := <-s.n.toSrv:
		return copy(p, pk.b), pk.addr, nil
	case <-s.n.srvDone:
		return 0, nil, net.ErrClosed
	}
}

func (s simServer) WriteTo(p []byte, addr net.Addr) (int, error) {
	s.n.mu.Lock()
	c := s.n.clients[addr.String()]
	s.n.mu.Unlock()
	if c == nil || c.dead.Load() {
		return len(p), nil
	}
	select {
	case c.rx <- pkt{b: append([]byte(nil), p...), addr: edgeAddr}:
	default:
	}
	return len(p), nil
}

func (s simServer) Close() error                     { return nil }
func (s simServer) LocalAddr() net.Addr              { return edgeAddr }
func (s simServer) SetDeadline(time.Time) error      { return nil }
func (s simServer) SetReadDeadline(time.Time) error  { return nil }
func (s simServer) SetWriteDeadline(time.Time) error { return nil }

// switchEdge is fakeEdge for many sessions over time: traffic from the internet
// goes to the newest session only, as at a real edge after a reconnect.
func switchEdge(t testingT, conn net.PacketConn, inetTun tunReadWriter, clientPrefix netip.Prefix) *atomic.Int32 {
	tlsc, _ := serverTLS(t)
	tmpl := uritemplate.MustNew("https://cloudflareaccess.com")
	var p connectip.Proxy
	var cur atomic.Pointer[connectip.Conn]
	sessions := new(atomic.Int32)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := inetTun.ReadPacket(buf)
			if err != nil {
				return
			}
			if c := cur.Load(); c != nil {
				_, _ = c.WritePacket(buf[:n])
			}
		}
	}()
	srv := &http3.Server{
		TLSConfig:       tlsc,
		EnableDatagrams: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req, err := connectip.ParseRequest(r, tmpl, "cf-connect-ip")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ipc, err := p.Proxy(w, req)
			if err != nil {
				return
			}
			sessions.Add(1)
			ctx := context.Background()
			_ = ipc.AssignAddresses(ctx, []netip.Prefix{clientPrefix})
			_ = ipc.AdvertiseRoute(ctx, []connectip.IPRoute{{
				StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255"),
			}})
			cur.Store(ipc)
			defer cur.CompareAndSwap(ipc, nil)
			for {
				b, err := ipc.ReadPacketZeroCopy(true)
				if err != nil {
					return
				}
				_ = inetTun.WritePacket(b)
			}
		}),
	}
	go func() { _ = srv.Serve(conn) }()
	return sessions
}

// resilienceRig is one usque tunnel over simNet to an echo origin.
type resilienceRig struct {
	n        *simNet
	sessions *atomic.Int32
	tnet     *netstack.Net
	origin   netip.Addr
	path     atomic.Value // string; "" means the network is unreachable
}

func newResilienceRig(ctx context.Context, t *testing.T, stall time.Duration, watchPath bool) *resilienceRig {
	r := &resilienceRig{n: newSimNet(), origin: netip.MustParseAddr("192.0.2.80")}
	r.path.Store("wifi")
	t.Cleanup(func() { close(r.n.srvDone) })

	inetTun, inet, err := netstack.CreateNetTUN([]netip.Addr{r.origin}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := inet.ListenTCPAddrPort(netip.AddrPortFrom(r.origin, 80))
	if err != nil {
		t.Fatal(err)
	}
	go echoSrc(ln)
	r.sessions = switchEdge(t, simServer{r.n}, api.NewNetstackAdapter(inetTun), netip.MustParsePrefix("172.16.0.2/32"))

	priv, err := genEC()
	if err != nil {
		t.Fatal(err)
	}
	c := &config.Config{PrivateKey: privKeyB64(t, priv), EndpointV4: "10.0.0.1", IPv4: "172.16.0.2", IPv6: "fd00::2"}
	cert, err := internal.GenerateCert(priv, &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := api.PrepareTlsConfig(priv, &priv.PublicKey, cert, "fake-edge", true)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := c.SelectEndpoint(false, false, 443)
	if err != nil {
		t.Fatal(err)
	}
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(c.IPv4)}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	r.tnet = tnet
	cfg := api.MaintainTunnelConfig{
		TLSConfig: tlsConfig, KeepalivePeriod: 10 * time.Second,
		InitialPacketSize: internal.DefaultInitialPacketSize, Endpoint: ep,
		Device: api.NewNetstackAdapter(dev), MTU: 1280, ReconnectDelay: time.Second,
		AlwaysReconnect: true,
		Underlay: &api.Underlay{ListenPacket: func(*net.UDPAddr) (net.PacketConn, error) {
			return r.n.newClient(), nil
		}},
		ConnectTimeout: 5 * time.Second,
	}
	if stall > 0 {
		cfg.StallTimeout = stall
		cfg.Probe = api.TCPProbe(tnet.DialContext, netip.AddrPortFrom(r.origin, 80).String())
	}
	if watchPath {
		cfg.WatchPath = true
		cfg.PathID = func() (string, error) {
			if p := r.path.Load().(string); p != "" {
				return p, nil
			}
			return "", errors.New("network is unreachable")
		}
	}
	go api.MaintainTunnel(ctx, cfg)

	if got := dialEchoThrough(ctx, t, tnet, r.origin); !has(got, "seen-from=172.16.0.2") {
		t.Fatalf("tunnel never came up: origin saw %q", got)
	}
	return r
}

func waitFor(t *testing.T, within time.Duration, what string, ok func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !ok() {
		if time.Since(start) > within {
			t.Fatalf("%s: not within %s", what, within)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return time.Since(start)
}

// The path dies silently while a connection is being opened. Without the stall
// check nothing notices until QUIC's 30s idle timeout; with it the tunnel is
// rebuilt in a few seconds and the waiting connection goes through.
func TestSilentDropIsRebuiltQuickly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	r := newResilienceRig(ctx, t, time.Second, false)
	if n := r.sessions.Load(); n != 1 {
		t.Fatalf("sessions before the drop = %d, want 1", n)
	}

	r.n.cut()
	start := time.Now()
	got := dialEchoThrough(ctx, t, r.tnet, r.origin)
	took := time.Since(start)
	if !has(got, "seen-from=172.16.0.2") {
		t.Fatalf("after the drop the origin saw %q", got)
	}
	if r.sessions.Load() < 2 {
		t.Fatal("the connection after the drop did not use a new session")
	}
	// Stall noticed after ~1-2s, probe fails after 2.5s, reconnect is immediate,
	// then the dial's next SYN retransmission (at ~7s) gets through.
	if took > 15*time.Second {
		t.Fatalf("recovered after %s, want well under QUIC's 30s idle timeout", took)
	}
	t.Logf("recovered from a silent drop in %s", took.Round(100*time.Millisecond))
}

// Switching networks (Wi-Fi -> mobile data) reconnects within about a second,
// even with no traffic to notice the old path is dead.
func TestNetworkSwitchReconnectsAtOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := newResilienceRig(ctx, t, 0, true)

	r.n.cut()
	r.path.Store("mobile")
	took := waitFor(t, 4*time.Second, "reconnect after a network switch", func() bool { return r.sessions.Load() >= 2 })
	t.Logf("reconnected %s after the network switch", took.Round(100*time.Millisecond))
	if got := dialEchoThrough(ctx, t, r.tnet, r.origin); !has(got, "seen-from=172.16.0.2") {
		t.Fatalf("after the switch the origin saw %q", got)
	}
}

// While the network is gone there is nothing to reconnect over; the moment it
// is back (here: the same Wi-Fi, same address) the tunnel is rebuilt.
func TestNetworkReturnReconnectsAtOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := newResilienceRig(ctx, t, 0, true)

	r.n.cut()
	r.path.Store("")
	time.Sleep(2500 * time.Millisecond)
	if n := r.sessions.Load(); n != 1 {
		t.Fatalf("reconnected %d times while the network was gone", n-1)
	}
	r.path.Store("wifi")
	took := waitFor(t, 4*time.Second, "reconnect after the network came back", func() bool { return r.sessions.Load() >= 2 })
	t.Logf("reconnected %s after the network came back", took.Round(100*time.Millisecond))
	if got := dialEchoThrough(ctx, t, r.tnet, r.origin); !has(got, "seen-from=172.16.0.2") {
		t.Fatalf("after the outage the origin saw %q", got)
	}
}
