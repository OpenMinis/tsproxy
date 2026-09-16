// Package proxy 实现基于 tsnet 出站拨号的本地 SOCKS5 与 HTTP/HTTPS 正向代理。
//
// 两个代理都不依赖第三方代理库，直接标准库实现，出站连接统一通过
// tsnet.Server.Dial（走 Tailscale 网络的 userspace netstack）发起，
// 这样代理转发出去的流量会经过 Tailscale（可达 tailnet 内部资源、
// 或经 exit node / subnet router 出网）。
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

// Dialer 是出站拨号函数的抽象，通常传入 (*tsnet.Server).Dial。
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// BasicAuth 用于 HTTP 代理的 Basic Auth 或 SOCKS5 的用户名密码认证。
type BasicAuth struct {
	User string
	Pass string
}

func (a BasicAuth) enabled() bool { return a.User != "" || a.Pass != "" }

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

// SOCKS5Server 是一个极简但完整（CONNECT 命令 + 可选用户名密码认证）的 SOCKS5 服务端。
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

// ListenAndServe 监听 addr 并处理 SOCKS5 连接，阻塞直到出错。
func (s *SOCKS5Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 监听 %s 失败: %w", addr, err)
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

	// --- 握手：版本 + 认证方法协商 ---
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
		s.logf("socks5: 客户端 %s 无可用认证方法", conn.RemoteAddr())
		return
	}

	if chosen == 0x02 {
		if !s.doUserPassAuth(conn, br) {
			return
		}
	}

	// --- 请求：CONNECT / BIND / UDP ASSOCIATE ---
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

	if cmd != 0x01 { // 仅支持 CONNECT（覆盖 SOCKS5 代理最主流场景）
		s.replySocks(conn, 0x07) // command not supported
		return
	}

	conn.SetDeadline(time.Time{})
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	upstream, err := s.Dial(dialCtx, "tcp", target)
	cancel()
	if err != nil {
		s.logf("socks5: 拨号 %s 失败: %v", target, err)
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
	case 0x03: // 域名
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
		return "", errors.New("不支持的地址类型")
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
// HTTP / HTTPS 正向代理
// ---------------------------------------------------------------------------

// HTTPProxyServer 是一个支持 HTTP 转发与 HTTPS（CONNECT 隧道）的正向代理。
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

// ListenAndServe 监听 addr 并处理 HTTP 代理连接，阻塞直到出错。
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

// handleConnect 处理 HTTPS 场景：客户端先发 CONNECT host:port，代理建立隧道后
// 双向透传加密流量（代理不解密 TLS，纯隧道转发）。
func (h *HTTPProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	dialCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	upstream, err := h.Dial(dialCtx, "tcp", r.Host)
	cancel()
	if err != nil {
		h.logf("http-connect: 拨号 %s 失败: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "服务端不支持 Hijack", http.StatusInternalServerError)
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

// handlePlainHTTP 处理明文 HTTP 请求转发（客户端把完整 URL 作为 RequestURI 发给代理）。
func (h *HTTPProxyServer) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHopHeaders(outReq.Header)

	transport := &http.Transport{
		DialContext: h.Dial,
	}
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		h.logf("http: 转发 %s 失败: %v", r.URL, err)
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

// relay 在两个连接间做双向全双工转发，任一方向结束/出错即退出。
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
