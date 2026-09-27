// Command tsproxy is a lightweight Tailscale client built on tsnet,
// exposing local SOCKS5 / HTTP(S) forward proxies so any other program on
// this machine can reach the Tailscale network.
//
// Usage:
//
//	tsproxy up                  Start the proxy (walks you through authorization on first run)
//	tsproxy status               Show the current node status
//	tsproxy logout                Log out and clear the local node identity
//	tsproxy version               Print version information
//
// Run `tsproxy up -h` to see all flags.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tailscale.com/ipn"

	"github.com/openminis/tsnet-proxy/internal/config"
	"github.com/openminis/tsnet-proxy/internal/proxy"
	"github.com/openminis/tsnet-proxy/internal/tsclient"
	"github.com/openminis/tsnet-proxy/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "up":
		cmdUp(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "logout":
		cmdLogout(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("tsproxy %s\n", version.String())
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`tsproxy — a tsnet-based Tailscale SOCKS5 / HTTP proxy gateway

Usage:
  tsproxy up [flags]       Start the Tailscale node + local proxy (walks you through authorization on first run)
  tsproxy status [flags]   Show the current node status
  tsproxy logout [flags]   Log out and clear the local node identity (re-authorization needed next time)
  tsproxy version          Print version information

Common flags (see 'tsproxy up -h' for the full list):
  -hostname string   Node name shown in the tailnet (defaults to the machine's hostname)
  -socks5 string     SOCKS5 listen address (default 127.0.0.1:1055, empty disables it)
  -http string        HTTP/HTTPS proxy listen address (default 127.0.0.1:1056, empty disables it)
  -authkey string      Pre-authorized key, skips interactive login (or use env var TS_AUTHKEY)
  -socks5-user/-socks5-pass   Enable username/password auth for SOCKS5
  -http-user/-http-pass       Enable Basic Auth for the HTTP proxy
  -exit-node string     Use the given exit node; all outbound traffic routes through it
  -exit-node-allow-lan-access  Still allow access to the local LAN while using an exit node
  -qr-file string        Path to save the auth QR code PNG (default state-dir/auth-qr.png)

Examples:
  tsproxy up
  tsproxy up -hostname my-laptop -socks5 127.0.0.1:1080 -http 127.0.0.1:8080
  tsproxy up -authkey tskey-auth-xxxxx -ephemeral
  TS_AUTHKEY=tskey-auth-xxxxx tsproxy up
`)
}

func cmdUp(args []string) {
	cfg, err := config.Parse(args)
	if err != nil {
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := tsclient.New(cfg)
	defer client.Server.Close()

	if err := client.StartAndAuth(ctx); err != nil {
		log.Fatalf("❌ startup failed: %v", err)
	}

	errCh := make(chan error, 2)

	if cfg.SOCKS5Addr != "" {
		s5 := &proxy.SOCKS5Server{
			Dial: client.Server.Dial,
			Auth: proxy.BasicAuth{User: cfg.SOCKS5User, Pass: cfg.SOCKS5Pass},
			Log:  log.New(os.Stderr, "[socks5] ", log.LstdFlags),
		}
		go func() {
			errCh <- s5.ListenAndServe(ctx, cfg.SOCKS5Addr)
		}()
		authNote := ""
		if s5.Auth.User != "" {
			authNote = fmt.Sprintf("(auth: %s / ******)", s5.Auth.User)
		}
		fmt.Printf("🧦 SOCKS5 proxy ready: socks5://%s %s\n", cfg.SOCKS5Addr, authNote)
	}

	if cfg.HTTPAddr != "" {
		hp := &proxy.HTTPProxyServer{
			Dial: client.Server.Dial,
			Auth: proxy.BasicAuth{User: cfg.HTTPUser, Pass: cfg.HTTPPass},
			Log:  log.New(os.Stderr, "[http]   ", log.LstdFlags),
		}
		go func() {
			errCh <- hp.ListenAndServe(ctx, cfg.HTTPAddr)
		}()
		authNote := ""
		if hp.Auth.User != "" {
			authNote = fmt.Sprintf("(auth: %s / ******)", hp.Auth.User)
		}
		fmt.Printf("🌐 HTTP/HTTPS proxy ready: http://%s %s\n", cfg.HTTPAddr, authNote)
	}

	fmt.Println()
	fmt.Println("Press Ctrl+C to stop the proxy and exit.")

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("❌ proxy server error: %v", err)
		}
	case <-ctx.Done():
		fmt.Println("\n👋 Received exit signal, shutting down…")
	}
}

func cmdStatus(args []string) {
	cfg, err := parseStateOnly(args)
	if err != nil {
		os.Exit(2)
	}
	client := tsclient.New(cfg)
	defer client.Server.Close()

	lc, err := client.Server.LocalClient()
	if err != nil {
		log.Fatalf("❌ failed to get local client: %v", err)
	}
	st, err := lc.Status(context.Background())
	if err != nil {
		log.Fatalf("❌ failed to get status (the node may never have been started): %v", err)
	}
	if st.BackendState != ipn.Running.String() {
		fmt.Printf("Status: %s (offline, run 'tsproxy up' to start)\n", st.BackendState)
		return
	}
	fmt.Printf("Status: %s\n", st.BackendState)
	if st.Self != nil {
		fmt.Printf("Node name: %s\n", st.Self.HostName)
		for _, ip := range st.Self.TailscaleIPs {
			fmt.Printf("Tailscale IP: %s\n", ip.String())
		}
	}
}

func cmdLogout(args []string) {
	cfg, err := parseStateOnly(args)
	if err != nil {
		os.Exit(2)
	}
	client := tsclient.New(cfg)
	defer client.Server.Close()

	lc, err := client.Server.LocalClient()
	if err != nil {
		log.Fatalf("❌ failed to get local client: %v", err)
	}
	if err := lc.Logout(context.Background()); err != nil {
		log.Fatalf("❌ logout failed: %v", err)
	}
	fmt.Println("✅ Logged out. Next run of 'tsproxy up' will require re-authorization (scan/click the link again).")
}

// parseStateOnly is used by the status/logout subcommands: they only need
// hostname/state-dir, so we reuse config.Parse with relaxed validation.
func parseStateOnly(args []string) (*config.Config, error) {
	// status/logout don't require a non-empty proxy address; borrow
	// config.Parse and relax the check by passing a dummy socks5 addr.
	cfg, err := config.Parse(append(args, "-socks5=127.0.0.1:0"))
	return cfg, err
}
