package mullvad

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const defaultPoolSize = 3

type ConnPool struct {
	timeout  time.Duration
	poolSize int
	mu       sync.Mutex
	pools    map[string]chan net.Conn
	logger   *slog.Logger
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewConnPool(timeout time.Duration, logger *slog.Logger) *ConnPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConnPool{
		timeout:  timeout,
		poolSize: defaultPoolSize,
		pools:    make(map[string]chan net.Conn),
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (cp *ConnPool) Stop() { cp.cancel() }

func (cp *ConnPool) Acquire(resolvedAddr string) (proxy.Dialer, bool) {
	cp.mu.Lock()
	pool, ok := cp.pools[resolvedAddr]
	if !ok {
		pool = make(chan net.Conn, cp.poolSize)
		cp.pools[resolvedAddr] = pool
		go cp.replenish(resolvedAddr, pool)
	}
	cp.mu.Unlock()

	select {
	case conn := <-pool:
		fwd := &staticDialer{conn: conn}
		d, err := proxy.SOCKS5("tcp", resolvedAddr, nil, fwd)
		if err != nil {
			conn.Close()
			return nil, false
		}
		return d, true
	default:
		return nil, false
	}
}

func (cp *ConnPool) replenish(addr string, pool chan net.Conn) {
	for {
		select {
		case <-cp.ctx.Done():
			return
		default:
		}

		d := &net.Dialer{Timeout: cp.timeout}
		conn, err := d.DialContext(cp.ctx, "tcp", addr)
		if err != nil {
			cp.logger.Debug("pool fill failed", "addr", addr, "error", err)
			time.Sleep(1 * time.Second)
			continue
		}

		select {
		case pool <- conn:
		case <-cp.ctx.Done():
			conn.Close()
			return
		default:
			conn.Close()
			time.Sleep(5 * time.Second)
		}
	}
}

type staticDialer struct{ conn net.Conn }

func (d *staticDialer) Dial(_, _ string) (net.Conn, error)               { return d.conn, nil }
func (d *staticDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) { return d.conn, nil }
