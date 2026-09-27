// Package proxy implements local SOCKS5 and HTTP/HTTPS forward proxies that
// dial outbound through tsnet.
//
// Neither proxy depends on a third-party proxy library — both are
// implemented directly against the standard library. Outbound connections
// all go through tsnet.Server.Dial (the Tailscale network's userspace
// netstack), so traffic forwarded by the proxy travels over Tailscale
// (reaching tailnet-internal resources, or exiting via an exit node /
// subnet router).
package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Dialer abstracts an outbound dial function, typically (*tsnet.Server).Dial.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// BasicAuth is used for the HTTP proxy's Basic Auth or SOCKS5's username/password auth.
type BasicAuth struct {
	User string
	Pass string
}

func (a BasicAuth) enabled() bool { return a.User != "" || a.Pass != "" }

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

// SOCKS5Server is a minimal but complete (CONNECT command + optional
// username/password auth) SOCKS5 server.
type SOCKS5Server struct {
	Dial Dialer
	Auth BasicAuth
	Log  *log.Logger
}

func (s *SOCKS5Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log.Printf(format, args...)
	}
}

// ListenAndServe listens on addr and handles SOCKS5 connections, blocking until an error occurs.
func (s *SOCKS5Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen on %s failed: %w", addr, err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *SOCKS5Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(conn)

	// --- Handshake: version + auth method negotiation ---
	ver, err := br.ReadByte()
	if err != nil || ver != 0x05 {
		return
	}
	nMethods, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	wantUserPass := s.Auth.enabled()
	chosen := byte(0xFF)
	for _, m := range methods {
		if wantUserPass && m == 0x02 {
			chosen = 0x02
			break
		}
		if !wantUserPass && m == 0x00 {
			chosen = 0x00
			break
		}
	}
	if _, err := conn.Write([]byte{0x05, chosen}); err != nil {
		return
	}
	if chosen == 0xFF {
		s.logf("socks5: client %s has no usable auth method", conn.RemoteAddr())
		return
	}

	if chosen == 0x02 {
		if !s.doUserPassAuth(conn, br) {
			return
		}
	}

	// --- Request: CONNECT / BIND / UDP ASSOCIATE ---
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	cmd := header[1]
	atyp := header[3]

	target, err := readSocksAddr(br, atyp)
	if err != nil {
		s.replySocks(conn, 0x01) // general failure
		return
	}

	if cmd != 0x01 { // only CONNECT is supported (covers the mainstream SOCKS5 proxy use case)
		s.replySocks(conn, 0x07) // command not supported
		return
	}

	conn.SetDeadline(time.Time{})
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	upstream, err := s.Dial(dialCtx, "tcp", target)
	cancel()
	if err != nil {
		s.logf("socks5: dial %s failed: %v", target, err)
		s.replySocks(conn, 0x05) // connection refused
		return
	}
	defer upstream.Close()

	if err := s.replySocksSuccess(conn); err != nil {
		return
	}

	relay(conn, upstream)
}

func (s *SOCKS5Server) doUserPassAuth(conn net.Conn, br *bufio.Reader) bool {
	verByte, err := br.ReadByte()
	if err != nil || verByte != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return false
	}
	ulen, err := br.ReadByte()
	if err != nil {
		return false
	}
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(br, uname); err != nil {
		return false
	}
	plen, err := br.ReadByte()
	if err != nil {
		return false
	}
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(br, passwd); err != nil {
		return false
	}

	okUser := subtle.ConstantTimeCompare(uname, []byte(s.Auth.User)) == 1
	okPass := subtle.ConstantTimeCompare(passwd, []byte(s.Auth.Pass)) == 1
	if okUser && okPass {
		conn.Write([]byte{0x01, 0x00})
		return true
	}
	conn.Write([]byte{0x01, 0x01})
	return false
}

func readSocksAddr(br *bufio.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03: // domain name
		l, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		return "", errors.New("unsupported address type")
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func (s *SOCKS5Server) replySocks(conn net.Conn, code byte) {
	conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (s *SOCKS5Server) replySocksSuccess(conn net.Conn) error {
	_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// ---------------------------------------------------------------------------
// HTTP / HTTPS forward proxy
// ---------------------------------------------------------------------------

// HTTPProxyServer is a forward proxy supporting both plain HTTP forwarding
// and HTTPS (CONNECT tunneling).
type HTTPProxyServer struct {
	Dial Dialer
	Auth BasicAuth
	Log  *log.Logger
}

func (h *HTTPProxyServer) logf(format string, args ...any) {
	if h.Log != nil {
		h.Log.Printf(format, args...)
	}
}

// ListenAndServe listens on addr and handles HTTP proxy connections, blocking until an error occurs.
func (h *HTTPProxyServer) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: h,
	}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (h *HTTPProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Auth.enabled() && !h.checkProxyAuth(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="tsproxy"`)
		http.Error(w, "407 Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.handlePlainHTTP(w, r)
}

func (h *HTTPProxyServer) checkProxyAuth(r *http.Request) bool {
	hdr := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(hdr, "Basic ") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic "))
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return false
	}
	okUser := subtle.ConstantTimeCompare([]byte(parts[0]), []byte(h.Auth.User)) == 1
	okPass := subtle.ConstantTimeCompare([]byte(parts[1]), []byte(h.Auth.Pass)) == 1
	return okUser && okPass
}

// handleConnect handles the HTTPS case: the client first sends
// CONNECT host:port, and once the proxy establishes the tunnel it relays
// encrypted traffic in both directions (the proxy never decrypts TLS, it's
// a pure tunnel).
func (h *HTTPProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	dialCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	upstream, err := h.Dial(dialCtx, "tcp", r.Host)
	cancel()
	if err != nil {
		h.logf("http-connect: dial %s failed: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "server does not support Hijack", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	relay(clientConn, upstream)
}

// handlePlainHTTP forwards plain HTTP requests (the client sends the full
// URL as the RequestURI to the proxy).
func (h *HTTPProxyServer) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHopHeaders(outReq.Header)

	transport := &http.Transport{
		DialContext: h.Dial,
	}
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		h.logf("http: forwarding %s failed: %v", r.URL, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailers", "Transfer-Encoding", "Upgrade",
}

func removeHopByHopHeaders(hdr http.Header) {
	for _, h := range hopByHopHeaders {
		hdr.Del(h)
	}
}

// relay does full-duplex bidirectional forwarding between two connections,
// exiting as soon as either side finishes or errors.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		if c, ok := a.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		if c, ok := b.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
