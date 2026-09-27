// Package tsclient wraps the creation and startup of a tsnet.Server plus a
// friendly interactive authorization flow.
//
// Core design:
//   - On first run (or once the key expires), Tailscale returns a one-time
//     authorization URL of the form https://login.tailscale.com/a/xxxxxxxxxxxx.
//   - This package prints that link prominently in the terminal, renders a
//     QR code (scan with your phone to authorize), tries to auto-open the
//     system default browser, and polls in the background until the user
//     completes authorization.
//   - If AuthKey is configured, all of the above is skipped and login
//     happens silently.
package tsclient

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
	qrcode "github.com/skip2/go-qrcode"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"

	"github.com/openminis/tsnet-proxy/internal/config"
)

// Client wraps a tsnet node that has been (or is being) started.
type Client struct {
	Server *tsnet.Server
	cfg    *config.Config
}

// New creates (but does not start) a tsnet node from the given config.
func New(cfg *config.Config) *Client {
	srv := &tsnet.Server{
		Hostname:   cfg.Hostname,
		Dir:        cfg.StateDir,
		AuthKey:    cfg.AuthKey,
		ControlURL: cfg.ControlURL,
		Ephemeral:  cfg.Ephemeral,
		UserLogf:   log.New(io.Discard, "", 0).Printf,
		Logf:       log.New(io.Discard, "", 0).Printf,
	}
	if cfg.Verbose {
		srv.Logf = log.New(os.Stderr, "[tsnet] ", log.LstdFlags).Printf
	}
	return &Client{Server: srv, cfg: cfg}
}

// StartAndAuth starts the node, shows a friendly authorization prompt
// (link + QR code + auto-open browser) if one is needed, and blocks until
// the node reaches Running state or ctx is canceled.
func (c *Client) StartAndAuth(ctx context.Context) error {
	fmt.Println(banner)
	fmt.Printf("🚀 Starting Tailscale client as node %q…\n", c.cfg.Hostname)
	fmt.Printf("   State dir: %s\n", c.cfg.StateDir)

	lc, err := c.Server.LocalClient()
	if err != nil {
		return fmt.Errorf("failed to get local control client: %w", err)
	}

	// watchCtx is independent of the outer ctx's cancellation: the auth
	// prompt needs to keep running in the background until Running is reached.
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()

	printedURL := ""
	authDone := make(chan struct{})
	watchErr := make(chan error, 1)

	go func() {
		defer close(authDone)
		watcher, err := lc.WatchIPNBus(watchCtx, ipn.NotifyInitialState|ipn.NotifyInitialNetMap)
		if err != nil {
			watchErr <- err
			return
		}
		defer watcher.Close()

		for {
			n, err := watcher.Next()
			if err != nil {
				if watchCtx.Err() != nil {
					return
				}
				watchErr <- err
				return
			}
			if n.ErrMessage != nil {
				fmt.Fprintf(os.Stderr, "⚠️  control plane returned an error: %s\n", *n.ErrMessage)
			}
			if n.BrowseToURL != nil && *n.BrowseToURL != printedURL {
				printedURL = *n.BrowseToURL
				printAuthPrompt(printedURL, c.cfg.QRFile, c.cfg.StateDir)
			}
			if n.State != nil {
				switch *n.State {
				case ipn.Running:
					fmt.Println("\n✅ Authorization succeeded! Tailscale node is online.")
					return
				case ipn.NeedsLogin:
					// Waiting for the user to complete the auth link; keep looping.
				case ipn.NeedsMachineAuth:
					fmt.Println("\n⏳ This node's authorization request has been submitted; waiting for an admin to approve it in the Tailscale admin console…")
					fmt.Println("   (open https://login.tailscale.com/admin/machines to approve it manually)")
				}
			}
		}
	}()

	// Trigger the actual startup/connection.
	if _, err := c.Server.Up(ctx); err != nil {
		cancelWatch()
		return fmt.Errorf("tsnet startup failed: %w", err)
	}

	select {
	case <-authDone:
	case err := <-watchErr:
		if err != nil {
			return fmt.Errorf("failed to watch authorization status: %w", err)
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	if c.cfg.ExitNode != "" {
		if err := c.applyExitNode(ctx, c.cfg.ExitNode, c.cfg.ExitNodeAllowLAN); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  failed to set exit node: %v\n", err)
		}
	}

	return c.printStatus(ctx)
}

// applyExitNode resolves ref (a node name or Tailscale IP) to a peer in the
// tailnet and sets it as this node's exit node — after this, all outbound
// traffic to non-tailnet (public) addresses is first encrypted and
// forwarded to that node, which then egresses it on this node's behalf.
//
// This is equivalent to the official CLI's `tailscale set --exit-node=<ref>`:
// it writes local Prefs and doesn't require any extra action from the
// peer (as long as it has already broadcast its exit-node identity via
// `tailscale set --advertise-exit-node` and the account ACL allows it).
func (c *Client) applyExitNode(ctx context.Context, ref string, allowLAN bool) error {
	lc, err := c.Server.LocalClient()
	if err != nil {
		return fmt.Errorf("failed to get local control client: %w", err)
	}

	st, err := lc.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get node status: %w", err)
	}

	peer, err := findExitNodePeer(st, ref)
	if err != nil {
		return err
	}
	if !peer.ExitNodeOption {
		return fmt.Errorf("node %q has not advertised itself as an exit node (it needs to run 'tailscale set --advertise-exit-node' and be approved by an admin)", ref)
	}

	maskedPrefs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ExitNodeID:             peer.ID,
			ExitNodeAllowLANAccess: allowLAN,
		},
		ExitNodeIDSet:             true,
		ExitNodeAllowLANAccessSet: true,
	}
	if _, err := lc.EditPrefs(ctx, maskedPrefs); err != nil {
		return fmt.Errorf("failed to write exit node preference: %w", err)
	}

	fmt.Printf("🚪 Exit node enabled: %s (%s)\n", peer.HostName, peer.TailscaleIPs)
	if allowLAN {
		fmt.Println("   (local LAN access is still allowed; everything else routes through this node)")
	} else {
		fmt.Println("   (all non-tailnet traffic will route through this node)")
	}
	return nil
}

// findExitNodePeer finds an exact match for ref (by hostname or Tailscale IP) in st's peer list.
func findExitNodePeer(st *ipnstate.Status, ref string) (*ipnstate.PeerStatus, error) {
	wantIP, isIP := netip.ParseAddr(ref)
	for _, p := range st.Peer {
		if isIP == nil {
			for _, ip := range p.TailscaleIPs {
				if ip == wantIP {
					return p, nil
				}
			}
		}
		if strings.EqualFold(p.HostName, ref) || strings.EqualFold(p.DNSName, ref) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no node %q found in the tailnet (run 'tsproxy status' or 'tailscale status' to see available node names/IPs)", ref)
}

func printAuthPrompt(url, qrFile, stateDir string) {
	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│  🔐 This device needs authorization to join your Tailscale network (tailnet) │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  Option 1 · Click/open the link to authorize:")
	fmt.Printf("    %s\n", hyperlink(url))
	fmt.Println("    (if your terminal doesn't support clickable hyperlinks, just copy the URL above into a browser)")
	fmt.Println()
	fmt.Println("  Option 2 · Scan with the Tailscale mobile app:")
	qrterminal.GenerateWithConfig(url, qrterminal.Config{
		Level:     qrterminal.M,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
	})

	if pngPath, err := writeQRPNG(url, qrFile, stateDir); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️  failed to generate the graphical QR code PNG: %v\n", err)
	} else if pngPath != "" {
		fmt.Println()
		fmt.Printf("  📷 Graphical QR code saved to: %s\n", pngPath)
		fmt.Println("     (you can send/display this image directly for phone scanning, same effect as the terminal QR code above)")
	}

	fmt.Println()
	fmt.Println("  Waiting for authorization to complete; the program will continue automatically once it does…")

	if tryOpenBrowser(url) {
		fmt.Println("  (attempted to open this link in your system's default browser)")
	}
}

// hyperlink wraps url as a clickable hyperlink using the OSC 8 terminal
// escape sequence. Terminals that support the protocol (iTerm2, Windows
// Terminal, most modern terminals) render the label as clickable; terminals
// that don't support it simply ignore the escape sequence and still display
// the full url, so copy/paste is unaffected.
func hyperlink(url string) string {
	const (
		oscStart = "\x1b]8;;"
		oscMid   = "\x1b\\"
		oscEnd   = "\x1b]8;;\x1b\\"
	)
	return oscStart + url + oscMid + url + oscEnd
}

// writeQRPNG generates a graphical QR code PNG file for the auth link.
// If qrFile is empty, it defaults to writing stateDir/auth-qr.png; if
// qrFile is "-", generation is skipped.
func writeQRPNG(url, qrFile, stateDir string) (string, error) {
	if qrFile == "-" {
		return "", nil
	}
	path := qrFile
	if path == "" {
		if stateDir == "" {
			stateDir = "."
		}
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return "", err
		}
		path = filepath.Join(stateDir, "auth-qr.png")
	}
	png, err := qrcode.Encode(url, qrcode.Medium, 512)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, png, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// tryOpenBrowser tries to open a browser using the current system's default
// mechanism; failures are silently ignored (the terminal prompt is enough
// on its own).
func tryOpenBrowser(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "linux":
		if _, err := exec.LookPath("xdg-open"); err == nil {
			cmd = exec.Command("xdg-open", url)
		} else {
			return false
		}
	default:
		return false
	}
	return cmd.Start() == nil
}

func (c *Client) printStatus(ctx context.Context) error {
	lc, err := c.Server.LocalClient()
	if err != nil {
		return err
	}
	st, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	printStatusSummary(st)
	return nil
}

func printStatusSummary(st *ipnstate.Status) {
	fmt.Println()
	fmt.Println("── Node info ─────────────────────────────────────────")
	if st.Self != nil {
		ips := make([]string, 0, len(st.Self.TailscaleIPs))
		for _, ip := range st.Self.TailscaleIPs {
			ips = append(ips, ip.String())
		}
		fmt.Printf("  Node name   : %s\n", st.Self.HostName)
		fmt.Printf("  Tailscale IP: %s\n", strings.Join(ips, ", "))
		fmt.Printf("  Account     : %s\n", st.Self.UserID.String())
	}
	fmt.Printf("  BackendState: %s\n", st.BackendState)
	fmt.Println("──────────────────────────────────────────────────────")
}

const banner = `
  ████████╗███████╗██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
  ╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
     ██║   ███████╗██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
     ██║   ╚════██║██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
     ██║   ███████║██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
     ╚═╝   ╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
     Tailscale SOCKS5 / HTTP Proxy Gateway · powered by tsnet
`

// WaitForLogout is a convenience wait helper (reserved: the CLI's logout
// subcommand may reuse it).
func WaitForLogout(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
