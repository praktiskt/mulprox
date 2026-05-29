package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/praktiskt/mulprox/internal/proxy"
	"github.com/praktiskt/mulprox/internal/stats"
	"github.com/praktiskt/mulprox/internal/util"
)

const (
	socks5Version = 0x05

	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xff

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	replySuccess        = 0x00
	replyGeneralFail    = 0x01
	replyNotAllowed     = 0x02
	replyNetworkUnreach = 0x03
	replyHostUnreach    = 0x04
	replyConnRefused    = 0x05
)

type Server struct {
	logger     *slog.Logger
	timeout    time.Duration
	mullvad    mullvad.ServerProvider
	stats      stats.Store
	baseFilter mullvad.Filter
	listener   net.Listener
	addr       string
	mu         sync.Mutex
	sem        chan struct{}
}

const maxConcurrentConns = 1000

func NewServer(logger *slog.Logger, timeout time.Duration, mv mullvad.ServerProvider, st stats.Store, baseFilter mullvad.Filter) *Server {
	return &Server{
		logger:     logger,
		timeout:    timeout,
		mullvad:    mv,
		stats:      st,
		baseFilter: baseFilter,
		sem:        make(chan struct{}, maxConcurrentConns),
	}
}

func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.addr = ln.Addr().String()
	s.mu.Unlock()
	return nil
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

func (s *Server) Serve() error {
	for {
		s.mu.Lock()
		ln := s.listener
		s.mu.Unlock()
		if ln == nil {
			return fmt.Errorf("server not listening")
		}
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				s.logger.Debug("temporary accept error", slog.String("error", err.Error()))
				continue
			}
			return err
		}
		s.sem <- struct{}{}
		go func() {
			defer func() { <-s.sem }()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	if err := clientConn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		s.logger.Debug("failed to set deadline", slog.String("error", err.Error()))
		return
	}

	// 1. Greeting
	auth, err := s.negotiateAuth(clientConn)
	if err != nil {
		s.logger.Debug("auth negotiation failed", slog.String("error", err.Error()))
		return
	}

	// 2. Request
	req, err := s.readRequest(clientConn)
	if err != nil {
		s.logger.Debug("failed to read request", slog.String("error", err.Error()))
		s.reply(clientConn, replyGeneralFail, nil)
		return
	}

	if req.cmd != cmdConnect {
		s.reply(clientConn, replyNotAllowed, nil)
		return
	}

	_ = clientConn.SetDeadline(time.Time{}) // clear deadline for long-lived tunnels

	target := net.JoinHostPort(req.dstHost, strconv.Itoa(req.dstPort))
	s.logger.Debug("SOCKS5 CONNECT", slog.String("target", target), slog.String("auth", auth.raw))

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	filter := s.baseFilter.Clone()
	if auth.filter != nil {
		auth.filter.ApplyTo(&filter)
	}

	server, err := s.resolveMullvad(ctx, filter)
	if err != nil {
		s.logger.Debug("failed to resolve Mullvad server", slog.String("error", err.Error()))
		s.reply(clientConn, replyGeneralFail, nil)
		return
	}

	remoteID := server.Hostname
	socksAddr := net.JoinHostPort(server.SOCKS5, strconv.Itoa(server.SOCKSPort))

	dialer, err := s.mullvad.SOCKS5DialerFromAddr(ctx, socksAddr, s.timeout)
	if err != nil {
		s.logger.Debug("failed to create SOCKS5 dialer", slog.String("error", err.Error()))
		s.reply(clientConn, replyGeneralFail, nil)
		return
	}

	targetConn, err := dialer.Dial("tcp", target)
	if err != nil {
		s.logger.Debug("failed to connect to target", slog.String("target", target), slog.String("error", err.Error()))
		if s.stats != nil {
			s.stats.RecordError(remoteID)
		}
		s.reply(clientConn, replyHostUnreach, nil)
		return
	}

	if err := s.reply(clientConn, replySuccess, targetConn.LocalAddr()); err != nil {
		targetConn.Close()
		s.logger.Debug("failed to write reply", slog.String("error", err.Error()))
		return
	}

	if s.stats != nil && remoteID != "" {
		s.stats.RecordRequest(remoteID)
	}

	util.Tunnel(clientConn, targetConn, remoteID, s.stats, s.logger)
}

type authResult struct {
	raw    string
	filter *proxy.ProxyAuth
}

func (s *Server) negotiateAuth(conn net.Conn) (authResult, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return authResult{}, fmt.Errorf("read version: %w", err)
	}
	if buf[0] != socks5Version {
		return authResult{}, fmt.Errorf("unsupported version %d", buf[0])
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return authResult{}, fmt.Errorf("read methods: %w", err)
	}

	// Prefer USERNAME/PASSWORD if offered, otherwise NO_AUTH
	hasNoAuth := false
	hasPassword := false
	for _, m := range methods {
		switch m {
		case authNone:
			hasNoAuth = true
		case authPassword:
			hasPassword = true
		}
	}

	if hasPassword {
		if _, err := conn.Write([]byte{socks5Version, authPassword}); err != nil {
			return authResult{}, err
		}
		return s.readPasswordAuth(conn)
	}

	if hasNoAuth {
		if _, err := conn.Write([]byte{socks5Version, authNone}); err != nil {
			return authResult{}, err
		}
		return authResult{raw: "none"}, nil
	}

	if _, err := conn.Write([]byte{socks5Version, authNoAccept}); err != nil {
		return authResult{}, err
	}
	return authResult{}, fmt.Errorf("no acceptable auth methods")
}

func (s *Server) readPasswordAuth(conn net.Conn) (authResult, error) {
	// Read [VER=1, ULEN, USERNAME, PLEN, PASSWORD]
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return authResult{}, fmt.Errorf("read auth header: %w", err)
	}
	if header[0] != 0x01 {
		return authResult{}, fmt.Errorf("unsupported auth version %d", header[0])
	}

	ulen := int(header[1])
	username := make([]byte, ulen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return authResult{}, fmt.Errorf("read username: %w", err)
	}

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return authResult{}, fmt.Errorf("read plen: %w", err)
	}
	plen := int(plenBuf[0])
	password := make([]byte, plen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return authResult{}, fmt.Errorf("read password: %w", err)
	}

	// Parse username as filter; silently accept invalid strings.
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return authResult{}, err
	}

	authStr := string(username)
	filter, err := proxy.ParseProxyAuth(authStr)
	if err != nil {
		// Invalid filter: still accept auth, use no filter
		s.logger.Debug("invalid SOCKS5 auth filter", slog.String("username", authStr), slog.String("error", err.Error()))
		return authResult{raw: authStr}, nil
	}
	return authResult{raw: authStr, filter: filter}, nil
}

type socks5Request struct {
	cmd     byte
	dstHost string
	dstPort int
}

func (s *Server) readRequest(conn net.Conn) (*socks5Request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read request header: %w", err)
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported version %d", header[0])
	}
	if header[2] != 0x00 {
		return nil, fmt.Errorf("non-zero reserved byte")
	}

	var host string
	switch header[3] {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		host = string(domain)
	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()
	default:
		return nil, fmt.Errorf("unsupported ATYP %d", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	return &socks5Request{cmd: header[1], dstHost: host, dstPort: port}, nil
}

func (s *Server) reply(conn net.Conn, rep byte, bindAddr net.Addr) error {
	var addr net.IP
	var port uint16
	atyp := byte(atypIPv4)

	if bindAddr != nil {
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok {
			addr = tcpAddr.IP
			port = uint16(tcpAddr.Port)
			if addr.To4() == nil && addr.To16() != nil {
				atyp = atypIPv6
			}
		}
	}

	resp := []byte{socks5Version, rep, 0x00, atyp}
	if atyp == atypIPv4 {
		if addr == nil {
			addr = net.IPv4zero
		}
		resp = append(resp, addr.To4()...)
	} else {
		if addr == nil {
			addr = net.IPv6zero
		}
		resp = append(resp, addr.To16()...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	resp = append(resp, portBuf...)

	_, err := conn.Write(resp)
	return err
}

func (s *Server) resolveMullvad(ctx context.Context, filter mullvad.Filter) (mullvad.Server, error) {
	server, err := s.mullvad.GetFilteredServerWithHealth(ctx, filter, func(hostname string) bool {
		if s.stats == nil {
			return true
		}
		health, ok := s.stats.PeekHealth(hostname)
		return !ok || health.Online
	})
	if err == nil {
		return server, nil
	}
	return s.mullvad.GetFilteredServer(ctx, filter)
}
