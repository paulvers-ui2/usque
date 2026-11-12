package api

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// --http2 leaves FallbackHTTP2Endpoint nil while FallbackHTTP2After keeps its
// default of 2. MaintainTunnel must not log.Fatalf on that (it used to exit 1).
func TestMaintainTunnelHTTP2IgnoresFallback(t *testing.T) {
	if os.Getenv("USQUE_HTTP2_CHILD") == "1" {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // return as soon as the startup checks have passed
		MaintainTunnel(ctx, MaintainTunnelConfig{
			Endpoint:           &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
			UseHTTP2:           true,
			FallbackHTTP2After: 2,
			MTU:                1280,
			Device:             nopDevice{},
		})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMaintainTunnelHTTP2IgnoresFallback$")
	cmd.Env = append(os.Environ(), "USQUE_HTTP2_CHILD=1")
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "requires a *net.TCPAddr endpoint") {
		t.Fatalf("MaintainTunnel exited on --http2 with the default fallback count:\n%s", out)
	}
}

type nopDevice struct{}

func (nopDevice) ReadPacket([]byte) (int, error) { select {} }
func (nopDevice) WritePacket([]byte) error       { return nil }
