// Package tsclient 封装 tsnet.Server 的创建、启动与友好的交互式授权流程。
//
// 核心设计：
//   - 首次运行（或密钥过期）时，Tailscale 会返回一个形如
//     https://login.tailscale.com/a/xxxxxxxxxxxx 的一次性授权链接。
//   - 本包会在终端里高亮打印该链接、渲染二维码（手机扫码即可授权），
//     并尝试用系统默认浏览器自动打开，同时后台轮询直到用户完成授权。
//   - 若配置了 AuthKey，则跳过以上交互，直接静默登录。
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

// Client 包装了一个已（或正在）启动的 tsnet 节点。
type Client struct {
	Server *tsnet.Server
	cfg    *config.Config
}

// New 根据配置创建（但不启动）一个 tsnet 节点。
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

// StartAndAuth 启动节点，若需要授权则展示友好的授权引导（链接+二维码+自动打开浏览器），
// 并阻塞直到节点进入 Running 状态或 ctx 被取消。
func (c *Client) StartAndAuth(ctx context.Context) error {
	fmt.Println(banner)
	fmt.Printf("🚀 正在以节点名 %q 启动 Tailscale 客户端…\n", c.cfg.Hostname)
	fmt.Printf("   状态目录: %s\n", c.cfg.StateDir)

	lc, err := c.Server.LocalClient()
	if err != nil {
		return fmt.Errorf("获取本地控制客户端失败: %w", err)
	}

	// watchCtx 独立于外层 ctx 的取消：授权引导需要在后台一直跑到拿到 Running 状态。
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
				fmt.Fprintf(os.Stderr, "⚠️  控制面返回错误: %s\n", *n.ErrMessage)
			}
			if n.BrowseToURL != nil && *n.BrowseToURL != printedURL {
				printedURL = *n.BrowseToURL
				printAuthPrompt(printedURL, c.cfg.QRFile, c.cfg.StateDir)
			}
			if n.State != nil {
				switch *n.State {
				case ipn.Running:
					fmt.Println("\n✅ 授权成功！Tailscale 节点已上线。")
					return
				case ipn.NeedsLogin:
					// 等待用户完成授权链接，继续循环
				case ipn.NeedsMachineAuth:
					fmt.Println("\n⏳ 该节点已提交授权申请，正在等待管理员在 Tailscale 后台批准…")
					fmt.Println("   （打开 https://login.tailscale.com/admin/machines 手动批准）")
				}
			}
		}
	}()

	// 触发实际的启动/连接。
	if _, err := c.Server.Up(ctx); err != nil {
		cancelWatch()
		return fmt.Errorf("tsnet 启动失败: %w", err)
	}

	select {
	case <-authDone:
	case err := <-watchErr:
		if err != nil {
			return fmt.Errorf("监听授权状态失败: %w", err)
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	if c.cfg.ExitNode != "" {
		if err := c.applyExitNode(ctx, c.cfg.ExitNode, c.cfg.ExitNodeAllowLAN); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  设置 exit node 失败: %v\n", err)
		}
	}

	return c.printStatus(ctx)
}

// applyExitNode 把 ref（节点名或 Tailscale IP）解析成 tailnet 中的对等节点，
// 并将其设为本节点的 exit node —— 之后所有经本代理发往非 tailnet 地址（公网）
// 的流量都会先加密转发给该节点，再由它代为出网。
//
// 这一步等价于官方 CLI 的 `tailscale set --exit-node=<ref>`：写入本地 Prefs，
// 不需要对方配合任何额外操作（前提是对方已用 `tailscale set --advertise-exit-node`
// 广播了 exit node 身份，且账号 ACL 允许使用）。
func (c *Client) applyExitNode(ctx context.Context, ref string, allowLAN bool) error {
	lc, err := c.Server.LocalClient()
	if err != nil {
		return fmt.Errorf("获取本地控制客户端失败: %w", err)
	}

	st, err := lc.Status(ctx)
	if err != nil {
		return fmt.Errorf("获取节点状态失败: %w", err)
	}

	peer, err := findExitNodePeer(st, ref)
	if err != nil {
		return err
	}
	if !peer.ExitNodeOption {
		return fmt.Errorf("节点 %q 未广播为 exit node（需要对方执行 'tailscale set --advertise-exit-node' 并经管理员批准）", ref)
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
		return fmt.Errorf("写入 exit node 偏好失败: %w", err)
	}

	fmt.Printf("🚪 已启用 exit node: %s (%s)\n", peer.HostName, peer.TailscaleIPs)
	if allowLAN {
		fmt.Println("   （已允许访问本机局域网，其余流量经该节点出网）")
	} else {
		fmt.Println("   （所有非 tailnet 流量将经该节点出网）")
	}
	return nil
}

// findExitNodePeer 在 status 的 peer 列表中按 hostname 或 Tailscale IP 精确匹配 ref。
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
	return nil, fmt.Errorf("在 tailnet 中未找到节点 %q（可用 'tsproxy status' 或 'tailscale status' 查看可用节点名/IP）", ref)
}

func printAuthPrompt(url, qrFile, stateDir string) {
	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│  🔐 需要授权此设备加入你的 Tailscale 网络（tailnet）           │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  方式一 · 点击/打开链接授权:")
	fmt.Printf("    %s\n", hyperlink(url))
	fmt.Println("    （若终端不支持超链接高亮，直接复制上面这行网址到浏览器打开即可）")
	fmt.Println()
	fmt.Println("  方式二 · 手机 Tailscale App 扫码授权:")
	qrterminal.GenerateWithConfig(url, qrterminal.Config{
		Level:     qrterminal.M,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
	})

	if pngPath, err := writeQRPNG(url, qrFile, stateDir); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️  图形二维码 PNG 生成失败: %v\n", err)
	} else if pngPath != "" {
		fmt.Println()
		fmt.Printf("  📷 图形二维码已保存: %s\n", pngPath)
		fmt.Println("     （可直接发送/展示该图片给手机扫码，效果等同上方终端二维码）")
	}

	fmt.Println()
	fmt.Println("  正在等待授权完成，授权后本程序会自动继续…")

	if tryOpenBrowser(url) {
		fmt.Println("  （已尝试用系统默认浏览器为你打开该链接）")
	}
}

// hyperlink 用 OSC 8 终端转义序列把 url 包装成可点击的超链接文本。
// 支持该协议的终端（iTerm2、Windows Terminal、大多数现代终端）会把 label 渲染为可点击项；
// 不支持的终端会忽略转义序列，仍然完整显示 url 本身，不影响复制粘贴。
func hyperlink(url string) string {
	const (
		oscStart = "\x1b]8;;"
		oscMid   = "\x1b\\"
		oscEnd   = "\x1b]8;;\x1b\\"
	)
	return oscStart + url + oscMid + url + oscEnd
}

// writeQRPNG 生成授权链接的图形二维码 PNG 文件。
// qrFile 为空时默认写入 stateDir/auth-qr.png；qrFile 为 "-" 时跳过生成。
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

// tryOpenBrowser 尝试用当前系统的默认方式打开浏览器，失败静默忽略（终端引导已足够）。
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
	fmt.Println("── 节点信息 ──────────────────────────────────────────")
	if st.Self != nil {
		ips := make([]string, 0, len(st.Self.TailscaleIPs))
		for _, ip := range st.Self.TailscaleIPs {
			ips = append(ips, ip.String())
		}
		fmt.Printf("  节点名      : %s\n", st.Self.HostName)
		fmt.Printf("  Tailscale IP: %s\n", strings.Join(ips, ", "))
		fmt.Printf("  所属账号    : %s\n", st.Self.UserID.String())
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
     Tailscale SOCKS5 / HTTP 代理网关 · tsnet 驱动
`

// WaitForLogout 提供一个便捷的等待函数（预留：CLI 的 logout 子命令可复用）。
func WaitForLogout(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
