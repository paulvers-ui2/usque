package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
	}()

	(*packetBufsPtr)[0] = pkt
	_, err := n.dev.Write(*packetBufsPtr, 0)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

// deviceErrorBackoff spaces out retries after the TUN device fails a read, so a
// closed device cannot spin the reader.
const deviceErrorBackoff = 100 * time.Millisecond

// pumpShutdownGrace bounds the wait for a connection's pumps after it is closed.
// They normally stop at once; this only keeps a stuck write from holding up
// the reconnect.
const pumpShutdownGrace = 2 * time.Second

// CONNECT-IP context ID 0 is encoded as a one-byte QUIC varint. Reserving this
// byte before packets lets connect-ip-go send outbound datagrams in place.
const datagramContextIDHeadroom = 1

// oversizeLogInterval bounds how often dropped oversize packets are logged.
const oversizeLogInterval = 30 * time.Second

// oversizeLog reports tunnel packets that did not fit in a QUIC DATAGRAM. connect-ip-go
// drops them and hands back an ICMP Packet Too Big, which netstack ignores, so without
// this log the only symptom is TCP connections through the tunnel stalling.
type oversizeLog struct {
	mu      sync.Mutex
	last    time.Time
	dropped int
}

// note records one dropped packet of size bytes and logs the count at most once per
// oversizeLogInterval.
func (o *oversizeLog) note(size int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.dropped++
	if now := time.Now(); now.Sub(o.last) >= oversizeLogInterval {
		log.Printf("Dropped %d tunnel packet(s) too large for a QUIC datagram (latest: %d bytes); raise --initial-packet-size or lower --mtu", o.dropped, size)
		o.last = now
		o.dropped = 0
	}
}

// MaintainTunnelConfig contains runtime settings for tunnel maintenance.
type MaintainTunnelConfig struct {
	TLSConfig         *tls.Config
	KeepalivePeriod   time.Duration
	InitialPacketSize uint16
	Endpoint          net.Addr
	Device            TunnelDevice
	MTU               int
	ReconnectDelay    time.Duration
	AlwaysReconnect   bool
	UseHTTP2          bool
	// Underlay, when set, carries the MASQUE connection over another tunnel
	// instead of the host network.
	Underlay *Underlay
	// OnConnect is a path to an executable run after every successful tunnel
	// connect. It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnConnect string
	// OnDisconnect is a path to an executable run after every tunnel loss.
	// It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnDisconnect string
	// HookEnv is a set of USQUE_* environment variables layered on top of the
	// parent process env for OnConnect / OnDisconnect invocations. USQUE_EVENT
	// and USQUE_ENDPOINT are set by MaintainTunnel itself.
	HookEnv map[string]string
	// FallbackHTTP2Endpoint and FallbackHTTP2After make an HTTP/3 tunnel switch to
	// HTTP/2 (TCP) after that many failed connects in a row, for networks that
	// drop or throttle UDP 443 (common on mobile data). The endpoint must be a
	// *net.TCPAddr. Zero / nil disables it; the switch lasts for the process.
	FallbackHTTP2Endpoint net.Addr
	FallbackHTTP2After    int

	// IdleTimeout is the QUIC idle timeout: a connection that hears nothing for
	// this long is closed and rebuilt. 0 keeps quic-go's default (30s).
	IdleTimeout time.Duration
	// ConnectTimeout bounds one connect attempt (TCP+TLS dial and CONNECT in
	// HTTP/2 mode, the CONNECT-IP request in both). 0 = no limit beyond QUIC's
	// own handshake timeout.
	ConnectTimeout time.Duration
	// WatchPath drops the connection as soon as the host network path to the
	// endpoint changes (e.g. Wi-Fi <-> mobile data) or comes back after an
	// outage, instead of waiting for the idle timeout. Ignored with an Underlay
	// unless PathID is set.
	WatchPath bool
	// PathID overrides how WatchPath identifies the current path; nil uses
	// RouteLocalAddr(Endpoint).
	PathID func() (string, error)
	// Probe and StallTimeout drop a connection that went quiet: once packets
	// have gone out with nothing coming back for StallTimeout, Probe runs (with
	// a timeout of at least 2.5s) and a failed probe drops the connection.
	// Probe should open a connection through this tunnel (see TCPProbe).
	Probe        func(ctx context.Context) error
	StallTimeout time.Duration
	// UnderlayHealthy, for a tunnel riding inside another one, holds off the
	// stall probe while the tunnel underneath is itself down or recovering.
	UnderlayHealthy func() bool
	// Health, when set, is kept up to date for others to read.
	Health *Health
	// Connected runs (in its own goroutine) after every successful connect.
	Connected func()
}

// cloneHookEnv returns a shallow copy of src so concurrent hook invocations
// do not share a map.
func cloneHookEnv(src map[string]string) map[string]string {
	out := make(map[string]string, len(src)+2)
	for k, v := range src {
		out[k] = v
	}
	return out
}

// sleepCtx sleeps for d or until ctx is cancelled, whichever comes first.
// Returns ctx.Err() on cancellation and nil on normal completion.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// devPacket is one packet read from the TUN device, stored after the headroom
// in buf, or the error the read returned.
type devPacket struct {
	buf []byte
	n   int
	err error
}

// readDevice is the only reader of the TUN device for the life of MaintainTunnel.
// Each connection's pump takes packets from out, so no pump is ever left parked
// in a device read when its connection dies: a reconnect does not wait for the
// next outbound packet, and that packet is not lost.
func readDevice(ctx context.Context, dev TunnelDevice, pool *NetBuffer, out chan<- devPacket) {
	for {
		buf := pool.Get()
		n, err := dev.ReadPacket(buf[datagramContextIDHeadroom:])
		if err != nil {
			pool.Put(buf)
			select {
			case out <- devPacket{err: err}:
			case <-ctx.Done():
				return
			}
			if sleepCtx(ctx, deviceErrorBackoff) != nil {
				return
			}
			continue
		}
		select {
		case out <- devPacket{buf: buf, n: n}:
		case <-ctx.Done():
			pool.Put(buf)
			return
		}
	}
}

// tunnelConn is one live MASQUE connection and what must be closed with it.
type tunnelConn struct {
	sock    net.PacketConn
	tr      *http3.Transport
	ipConn  *connectip.Conn
	rsp     *http.Response
	release func()
	cancel  context.CancelFunc
}

func (c *tunnelConn) close() {
	if c.ipConn != nil {
		_ = c.ipConn.Close()
	}
	if c.release != nil {
		c.release()
	}
	if c.tr != nil {
		_ = c.tr.Close()
	}
	if c.sock != nil {
		_ = c.sock.Close()
	}
	if c.cancel != nil {
		c.cancel()
	}
}

// connectOnce makes one connect attempt, bounded by cfg.ConnectTimeout. The
// connection's context lives until close (an HTTP/2 CONNECT stream lives only as
// long as its request context).
func connectOnce(ctx context.Context, cfg *MaintainTunnelConfig, quicConfig *quic.Config, endpoint net.Addr, useHTTP2 bool) (*tunnelConn, error) {
	connCtx, cancel := context.WithCancel(ctx)
	var timer *time.Timer
	if cfg.ConnectTimeout > 0 {
		timer = time.AfterFunc(cfg.ConnectTimeout, cancel)
	}
	sock, tr, ipConn, rsp, release, err := connectTunnelOver(connCtx, cfg.TLSConfig, quicConfig, internal.ConnectURI, endpoint, useHTTP2, cfg.Underlay)
	c := &tunnelConn{sock: sock, tr: tr, ipConn: ipConn, rsp: rsp, release: release, cancel: cancel}
	if timer != nil && !timer.Stop() {
		// The timeout fired: whatever came back is unusable or already failing.
		if err == nil {
			err = fmt.Errorf("connect took longer than %s", cfg.ConnectTimeout)
		} else {
			err = fmt.Errorf("no tunnel within %s: %w", cfg.ConnectTimeout, err)
		}
	}
	if err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
// See health.go for how a connection that died silently is noticed early.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - cfg: MaintainTunnelConfig - Tunnel maintenance runtime configuration.
func MaintainTunnel(ctx context.Context, cfg MaintainTunnelConfig) {
	if cfg.UseHTTP2 {
		if _, ok := cfg.Endpoint.(*net.TCPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/2 mode requires a *net.TCPAddr endpoint, got %T", cfg.Endpoint)
		}
	} else {
		if _, ok := cfg.Endpoint.(*net.UDPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/3 mode requires a *net.UDPAddr endpoint, got %T", cfg.Endpoint)
		}
	}
	if cfg.FallbackHTTP2After > 0 {
		if _, ok := cfg.FallbackHTTP2Endpoint.(*net.TCPAddr); !ok {
			log.Fatalf("MaintainTunnel: the HTTP/2 fallback requires a *net.TCPAddr endpoint, got %T", cfg.FallbackHTTP2Endpoint)
		}
	}

	// The transport in use; the HTTP/2 fallback may switch it below.
	endpoint, useHTTP2 := cfg.Endpoint, cfg.UseHTTP2
	quicFailures := 0

	quicConfig := internal.DefaultQuicConfig(cfg.KeepalivePeriod, cfg.InitialPacketSize)
	if cfg.IdleTimeout > 0 {
		quicConfig.MaxIdleTimeout = cfg.IdleTimeout
	}
	health := cfg.Health
	if health == nil {
		health = new(Health)
	}
	var pathID func() (string, error)
	if cfg.WatchPath {
		pathID = cfg.PathID
		if pathID == nil && cfg.Underlay == nil {
			pathID = RouteLocalAddr(cfg.Endpoint)
		}
	}
	watching := pathID != nil || (cfg.Probe != nil && cfg.StallTimeout > 0)

	packetBufferPool := NewNetBuffer(cfg.MTU + datagramContextIDHeadroom)
	var oversize oversizeLog
	outbound := make(chan devPacket)
	go readDevice(ctx, cfg.Device, packetBufferPool, outbound)

	// carry is a packet taken from the device that has not been sent yet: the one
	// that ended the idle wait, or one the last connection's pump picked up just
	// as that connection ended. The next connection sends it first.
	var carry *devPacket

	for {
		if ctx.Err() != nil {
			return
		}

		if !cfg.AlwaysReconnect && carry == nil {
			log.Println("Tunnel idle. Waiting for outbound activity before reconnecting...")
			var p devPacket
			select {
			case p = <-outbound:
			case <-ctx.Done():
				return
			}
			if p.err != nil {
				log.Printf("Failed to read from TUN device while waiting for activity: %v", p.err)
				if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
					return
				}
				continue
			}
			carry = &p
			log.Printf("Detected outbound activity (%d bytes). Reconnecting...", p.n)
		}

		log.Printf("Establishing MASQUE connection to %s", endpoint)
		conn, err := connectOnce(ctx, &cfg, quicConfig, endpoint, useHTTP2)
		if err != nil {
			log.Printf("Failed to connect tunnel: %v", err)
			if !useHTTP2 && cfg.FallbackHTTP2After > 0 {
				quicFailures++
				if quicFailures >= cfg.FallbackHTTP2After {
					log.Printf("QUIC failed %d times in a row; falling back to HTTP/2 via %s", quicFailures, cfg.FallbackHTTP2Endpoint)
					endpoint, useHTTP2 = cfg.FallbackHTTP2Endpoint, true
				}
			}
			if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
				return
			}
			continue
		}
		if conn.rsp.StatusCode != 200 {
			log.Printf("Tunnel connection failed: %s", conn.rsp.Status)
			conn.close()
			if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
				return
			}
			continue
		}

		log.Println("Connected to MASQUE server")
		quicFailures = 0
		health.setConnected(true)
		ipConn := conn.ipConn
		// Fixed for this connection's pumps, even if a later iteration falls back.
		connHTTP2 := useHTTP2

		if cfg.OnConnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "connect"
			env["USQUE_ENDPOINT"] = endpoint.String()
			RunHook(cfg.OnConnect, env)
		}
		if cfg.Connected != nil {
			go cfg.Connected()
		}

		// Up to three senders: both pumps and the health watcher.
		errChan := make(chan error, 3)
		pumpCtx, cancelPumps := context.WithCancel(ctx)
		var wg sync.WaitGroup
		var unsent atomic.Pointer[devPacket]

		wg.Add(2)

		go func(first *devPacket) {
			defer wg.Done()
			// forward sends the n-byte packet stored after the headroom in buf, then
			// returns buf to the pool. It returns false when the pump must stop.
			forward := func(buf []byte, n int) bool {
				icmp, err := ipConn.WritePacketBuffer(buf, datagramContextIDHeadroom, n)
				packetBufferPool.Put(buf)
				if err != nil {
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while writing to IP connection: %w", err)
						return false
					}
					log.Printf("Error writing to IP connection: %v, continuing...", err)
					return true
				}
				health.sent()

				if len(icmp) > 0 {
					// connect-ip-go only returns an ICMP packet for a packet too large to send.
					oversize.note(n)
					if err := cfg.Device.WritePacket(icmp); err != nil {
						if errors.As(err, new(*connectip.CloseError)) {
							errChan <- fmt.Errorf("connection closed while writing ICMP to TUN device: %w", err)
							return false
						}
						log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
					}
				}
				return true
			}

			if first != nil && !forward(first.buf, first.n) {
				return
			}
			for {
				var p devPacket
				select {
				case <-pumpCtx.Done():
					return
				case p = <-outbound:
				}
				if p.err != nil {
					errChan <- fmt.Errorf("failed to read from TUN device: %w", p.err)
					return
				}
				if pumpCtx.Err() != nil {
					// Lost the race with the end of this connection: keep the
					// packet for the next one instead of dropping it.
					unsent.Store(&p)
					return
				}
				if !forward(p.buf, p.n) {
					return
				}
			}
		}(carry)
		carry = nil

		go func() {
			defer wg.Done()
			for {
				packet, err := ipConn.ReadPacketZeroCopy(true)
				if err != nil {
					if connHTTP2 {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %w", err)
						return
					}
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %w", err)
						return
					}
					log.Printf("Error reading from IP connection: %v, continuing...", err)
					continue
				}
				health.received()
				if err := cfg.Device.WritePacket(packet); err != nil {
					errChan <- fmt.Errorf("failed to write to TUN device: %w", err)
					return
				}
			}
		}()

		if watching {
			var path *pathWatch
			if pathID != nil {
				path = newPathWatch(pathID)
			}
			go watchHealth(pumpCtx, health, path, cfg.Probe, cfg.StallTimeout, cfg.UnderlayHealthy, errChan)
		}

		err = <-errChan
		log.Printf("Tunnel connection lost: %v. Reconnecting...", err)
		health.setConnected(false)

		if cfg.OnDisconnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "disconnect"
			env["USQUE_ENDPOINT"] = endpoint.String()
			RunHook(cfg.OnDisconnect, env)
		}

		cancelPumps()
		conn.close()
		// Both pumps end promptly: the device pump selects on pumpCtx and the IP
		// pump's reads fail once ipConn is closed.
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(pumpShutdownGrace):
			log.Printf("Pumps still busy %s after the connection closed; reconnecting anyway", pumpShutdownGrace)
		}
		carry = unsent.Swap(nil)

		if errors.Is(err, errPathChanged) || errors.Is(err, errStalled) {
			// The old connection is gone for good and the cause is known; a new
			// connection (on the new path) is worth trying right away.
			continue
		}
		if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
			return
		}
	}
}
