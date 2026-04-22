package util

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/praktiskt/mulprox/internal/stats"
)

const copyBufSize = 32 * 1024
const tunnelIdleTimeout = 5 * time.Minute

var BufferPool = sync.Pool{
	New: func() any {
		return make([]byte, copyBufSize)
	},
}

type CountingReader struct {
	Reader io.Reader
	Count  *int64
}

func (c *CountingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	*c.Count += int64(n)
	return n, err
}

// Tunnel copies data bidirectionally between client and target connections
// and records stats via the provided store.
func Tunnel(clientConn, targetConn net.Conn, remoteID string, st stats.Store, logger *slog.Logger) {
	buf1 := BufferPool.Get().([]byte)
	buf2 := BufferPool.Get().([]byte)
	defer BufferPool.Put(buf1)
	defer BufferPool.Put(buf2)

	var sent, received int64

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.CopyBuffer(targetConn, &CountingReader{Reader: clientConn, Count: &sent}, buf1)
		targetConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.CopyBuffer(clientConn, &CountingReader{Reader: targetConn, Count: &received}, buf2)
		clientConn.Close()
	}()

	extendDeadline := func() {
		t := time.Now().Add(tunnelIdleTimeout)
		clientConn.SetReadDeadline(t)
		targetConn.SetReadDeadline(t)
	}
	extendDeadline()

	var lastSent, lastRecv int64
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	for {
		select {
		case <-ticker.C:
			deltaSent := sent - lastSent
			deltaRecv := received - lastRecv
			if deltaSent > 0 || deltaRecv > 0 {
				if st != nil && remoteID != "" {
					st.RecordBytes(remoteID, deltaSent, deltaRecv)
				}
				lastSent = sent
				lastRecv = received
				extendDeadline()
			}
		case <-done:
			ticker.Stop()
			deltaSent := sent - lastSent
			deltaRecv := received - lastRecv
			if deltaSent > 0 || deltaRecv > 0 {
				if st != nil && remoteID != "" {
					st.RecordBytes(remoteID, deltaSent, deltaRecv)
				}
			}
			return
		}
	}
}
