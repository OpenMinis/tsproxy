// Package config manages tsnet-proxy's runtime configuration: command-line
// flag parsing, defaults, and locating the state directory (where tsnet
// persists node state/keys).
package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds all parameters needed for one run.
type Config struct {
	// Hostname is the name this node shows up as in the Tailscale network (visible within the tailnet).
	Hostname string
	// StateDir is the directory where tsnet persists node identity/keys.
	StateDir string
	// AuthKey is optional: use a pre-authorized key for silent login, skipping the interactive auth link.
	AuthKey string
	// ControlURL is optional: a self-hosted Headscale / private control plane address.
	ControlURL string
	// Ephemeral, when true, automatically removes the node from the tailnet on exit (good for CI/one-off use).
	Ephemeral bool

	// SOCKS5Addr is the local listen address; an empty string disables the SOCKS5 proxy.
	SOCKS5Addr string
	// HTTPAddr is the local listen address; an empty string disables the HTTP/HTTPS proxy.
	HTTPAddr string

	// SOCKS5User / SOCKS5Pass are optional: set username/password authentication for the SOCKS5 proxy.
	SOCKS5User string
	SOCKS5Pass string
	// HTTPUser / HTTPPass are optional: set Basic Auth authentication for the HTTP proxy.
	HTTPUser string
	HTTPPass string

	// Verbose turns on more detailed logging (including tsnet's own internal logs; silent by default).
	Verbose bool

	// QRFile is the output path for the auth link's graphical QR code PNG; an empty string
	// uses the default filename under StateDir. Set to "-" to disable generating the PNG file
	// (the terminal ASCII QR code is still printed).
	QRFile string

	// AcceptRoutes controls whether to accept subnet routes advertised by other nodes.
	AcceptRoutes bool
	// ExitNode is optional: use the given exit node (IP or node name); all outbound traffic routes through it.
	ExitNode string
	// ExitNodeAllowLAN controls whether the local LAN is still reachable while using an exit node.
	ExitNodeAllowLAN bool
}

func defaultStateDir() string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "tsproxy")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tsproxy-state"
	}
	return filepath.Join(home, ".tsproxy", "state")
}

// Parse parses command-line flags (excluding the subcommand itself; callers
// should pass Args()[1:]).
func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("tsproxy up", flag.ContinueOnError)
	c := &Config{}

	fs.StringVar(&c.Hostname, "hostname", defaultHostname(), "node name shown in the Tailscale network")
	fs.StringVar(&c.StateDir, "state-dir", defaultStateDir(), "local directory for storing node identity/keys")
	fs.StringVar(&c.AuthKey, "authkey", os.Getenv("TS_AUTHKEY"), "pre-authorized key (or use env var TS_AUTHKEY); leave empty for the interactive login link")
	fs.StringVar(&c.ControlURL, "control-url", os.Getenv("TS_CONTROL_URL"), "self-hosted control plane address (e.g. Headscale); leave empty to use official Tailscale")
	fs.BoolVar(&c.Ephemeral, "ephemeral", false, "ephemeral node; automatically removed from the tailnet on exit")

	fs.StringVar(&c.SOCKS5Addr, "socks5", "127.0.0.1:1055", "SOCKS5 proxy listen address; empty disables it")
	fs.StringVar(&c.HTTPAddr, "http", "127.0.0.1:1056", "HTTP/HTTPS proxy listen address; empty disables it")

	fs.StringVar(&c.SOCKS5User, "socks5-user", "", "SOCKS5 proxy username (optional, combine with -socks5-pass to enable auth)")
	fs.StringVar(&c.SOCKS5Pass, "socks5-pass", "", "SOCKS5 proxy password")
	fs.StringVar(&c.HTTPUser, "http-user", "", "HTTP proxy Basic Auth username (optional)")
	fs.StringVar(&c.HTTPPass, "http-pass", "", "HTTP proxy Basic Auth password")

	fs.BoolVar(&c.Verbose, "verbose", false, "print verbose logs (including tsnet's internal logs)")
	fs.StringVar(&c.QRFile, "qr-file", "", "output path for the auth QR code PNG (defaults to state-dir/auth-qr.png, pass '-' to disable)")
	fs.BoolVar(&c.AcceptRoutes, "accept-routes", true, "accept subnet routes advertised by other nodes")
	fs.StringVar(&c.ExitNode, "exit-node", "", "use the given exit node (node name or IP); all outbound traffic routes through it")
	fs.BoolVar(&c.ExitNodeAllowLAN, "exit-node-allow-lan-access", false, "still allow access to the local LAN while using an exit node")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if c.SOCKS5Addr == "" && c.HTTPAddr == "" {
		return nil, fmt.Errorf("at least one proxy must be enabled: -socks5 and -http cannot both be empty")
	}
	return c, nil
}

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "tsproxy"
	}
	return h
}
