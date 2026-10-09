package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/internal"
)

func TestPathWatch(t *testing.T) {
	cur, fail := "10.0.0.5", false
	id := func() (string, error) {
		if fail {
			return "", errors.New("network is unreachable")
		}
		return cur, nil
	}
	p := newPathWatch(id)
	if why := p.check(); why != "" {
		t.Fatalf("unchanged path reported %q", why)
	}
	cur = "100.64.1.9" // Wi-Fi -> mobile data
	if why := p.check(); !strings.Contains(why, "10.0.0.5 -> 100.64.1.9") {
		t.Fatalf("address change reported %q", why)
	}

	p = newPathWatch(id)
	fail = true
	if why := p.check(); why != "" {
		t.Fatalf("an unreachable network is nothing to reconnect over, got %q", why)
	}
	fail = false // same address once the network is back
	if why := p.check(); !strings.Contains(why, "network is back") {
		t.Fatalf("network return reported %q", why)
	}
}

func TestTCPProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	d := (&net.Dialer{}).DialContext
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := TCPProbe(d, ln.Addr().String())(ctx); err != nil {
		t.Fatalf("probe to a listener: %v", err)
	}

	refused := func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("connect: connection refused")
	}
	if err := TCPProbe(refused, "192.0.2.1:443")(ctx); err != nil {
		t.Fatalf("a refused probe still proves the tunnel answers, got %v", err)
	}

	silent := func(ctx context.Context, network, address string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	sctx, scancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer scancel()
	if err := TCPProbe(silent, "192.0.2.1:443")(sctx); err == nil {
		t.Fatal("a probe that hears nothing must fail")
	}
}

func TestHealthStallClock(t *testing.T) {
	var h Health
	if h.Healthy() {
		t.Fatal("not connected yet, but healthy")
	}
	h.setConnected(true)
	if !h.Healthy() || h.unansweredFor() != 0 {
		t.Fatal("fresh connection should be healthy with nothing pending")
	}
	h.sent()
	first := h.pending.Load()
	time.Sleep(20 * time.Millisecond)
	h.sent()
	if h.pending.Load() != first {
		t.Fatal("the stall clock must keep the oldest unanswered packet")
	}
	if h.unansweredFor() < 20*time.Millisecond {
		t.Fatalf("unansweredFor = %v", h.unansweredFor())
	}
	h.received()
	if h.unansweredFor() != 0 {
		t.Fatal("a received packet answers everything pending")
	}
	h.pending.Store(monoNow() - int64(healthyStallGrace) - int64(time.Second))
	if h.Healthy() {
		t.Fatal("unanswered for longer than the grace, still healthy")
	}
}

// A dead network underneath an HTTP/2 tunnel used to hang the connect for as
// long as the OS TCP timeout (minutes). ConnectTimeout bounds it.
func TestConnectTimeoutBoundsHTTP2Dial(t *testing.T) {
	blackhole := &Underlay{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	cfg := MaintainTunnelConfig{
		TLSConfig:      &tls.Config{InsecureSkipVerify: true},
		Underlay:       blackhole,
		ConnectTimeout: 300 * time.Millisecond,
	}
	start := time.Now()
	_, err := connectOnce(context.Background(), &cfg, internal.DefaultQuicConfig(0, 0), &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, true)
	if err == nil {
		t.Fatal("connect over a black hole succeeded")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("connect gave up after %v, want about 300ms", took)
	}
}
