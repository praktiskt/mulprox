package util

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// benchConn satisfies net.Conn via two unidirectional io.Pipes.
type benchConn struct {
	read  io.ReadCloser
	write io.WriteCloser
}

func newBenchConn() (*benchConn, io.WriteCloser, io.ReadCloser) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &benchConn{read: r1, write: w2}, w1, r2
}

func (c *benchConn) Read(p []byte) (int, error)         { return c.read.Read(p) }
func (c *benchConn) Write(p []byte) (int, error)        { return c.write.Write(p) }
func (c *benchConn) Close() error                        { c.read.Close(); return c.write.Close() }
func (c *benchConn) LocalAddr() net.Addr                { return benchAddr{} }
func (c *benchConn) RemoteAddr() net.Addr               { return benchAddr{} }
func (c *benchConn) SetDeadline(t time.Time) error      { return nil }
func (c *benchConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *benchConn) SetWriteDeadline(t time.Time) error { return nil }

type benchAddr struct{}

func (benchAddr) Network() string { return "bench" }
func (benchAddr) String() string  { return "bench" }

// BenchmarkTunnel measures bidirectional copy throughput.
func BenchmarkTunnel(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 65536},
		{"1MB", 1048576},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			data := make([]byte, sz.size)
			b.SetBytes(int64(sz.size * 2))
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				client, cw, cr := newBenchConn()
				target, tw, tr := newBenchConn()
				go io.Copy(io.Discard, cr)
				go io.Copy(io.Discard, tr)
				go func() { cw.Write(data); cw.Close() }()
				go func() { tw.Write(data); tw.Close() }()

				b.StartTimer()
				Tunnel(client, target, "bench", nil, logger)
				b.StopTimer()
			}
		})
	}
}
