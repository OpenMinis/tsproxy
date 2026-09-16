// Package config 管理 tsnet-proxy 的运行配置：命令行参数解析、
// 默认值、以及状态目录（存放 tsnet 的节点状态/密钥）的定位。
package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// Config 保存一次运行所需的全部参数。
type Config struct {
	// Hostname 是本节点在 Tailscale 网络中显示的名字（tailnet 内可见）。
	Hostname string
	// StateDir 是 tsnet 持久化节点身份/密钥的目录。
	StateDir string
	// AuthKey 可选：使用预授权密钥（Auth Key）静默登录，跳过交互式授权链接。
	AuthKey string
	// ControlURL 可选：自建 Headscale / 私有 control plane 地址。
	ControlURL string
	// Ephemeral 为 true 时节点退出后自动从 tailnet 中移除（适合临时/CI 场景）。
	Ephemeral bool

	// SOCKS5Addr 本地监听地址，空字符串表示不开启 SOCKS5 代理。
	SOCKS5Addr string
	// HTTPAddr 本地监听地址，空字符串表示不开启 HTTP/HTTPS 代理。
	HTTPAddr string

	// SOCKS5User / SOCKS5Pass 可选：为 SOCKS5 代理设置用户名密码认证。
	SOCKS5User string
	SOCKS5Pass string
	// HTTPUser / HTTPPass 可选：为 HTTP 代理设置 Basic Auth 认证。
	HTTPUser string
	HTTPPass string

	// Verbose 打开更详细的日志（包括 tsnet 自身日志，默认静默）。
	Verbose bool

	// QRFile 授权链接的图形二维码 PNG 输出路径，空字符串表示使用 StateDir 下的默认文件名。
	// 设为 "-" 可禁用图形二维码文件的生成（仍会打印终端 ASCII 二维码）。
	QRFile string

	// AcceptRoutes 是否接受其他节点通告的子网路由（subnet routes）。
	AcceptRoutes bool
	// ExitNode 可选：使用指定的 exit node（IP 或节点名），所有出站流量经其转发。
	ExitNode string
	// ExitNodeAllowLAN 使用 exit node 时是否仍允许访问本机所在局域网。
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

// Parse 解析命令行参数（不包含子命令本身，调用方需先 Args()[1:]）。
func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("tsproxy up", flag.ContinueOnError)
	c := &Config{}

	fs.StringVar(&c.Hostname, "hostname", defaultHostname(), "在 Tailscale 网络中显示的节点名")
	fs.StringVar(&c.StateDir, "state-dir", defaultStateDir(), "节点身份/密钥的本地存储目录")
	fs.StringVar(&c.AuthKey, "authkey", os.Getenv("TS_AUTHKEY"), "预授权密钥（可用环境变量 TS_AUTHKEY），留空则走交互式登录链接")
	fs.StringVar(&c.ControlURL, "control-url", os.Getenv("TS_CONTROL_URL"), "自建 control plane 地址（如 Headscale），留空使用官方 Tailscale")
	fs.BoolVar(&c.Ephemeral, "ephemeral", false, "临时节点，进程退出后自动从 tailnet 移除")

	fs.StringVar(&c.SOCKS5Addr, "socks5", "127.0.0.1:1055", "SOCKS5 代理监听地址，留空禁用")
	fs.StringVar(&c.HTTPAddr, "http", "127.0.0.1:1056", "HTTP/HTTPS 代理监听地址，留空禁用")

	fs.StringVar(&c.SOCKS5User, "socks5-user", "", "SOCKS5 代理用户名（可选，配合 -socks5-pass 开启认证）")
	fs.StringVar(&c.SOCKS5Pass, "socks5-pass", "", "SOCKS5 代理密码")
	fs.StringVar(&c.HTTPUser, "http-user", "", "HTTP 代理 Basic Auth 用户名（可选）")
	fs.StringVar(&c.HTTPPass, "http-pass", "", "HTTP 代理 Basic Auth 密码")

	fs.BoolVar(&c.Verbose, "verbose", false, "打印详细日志（含 tsnet 内部日志）")
	fs.StringVar(&c.QRFile, "qr-file", "", "授权二维码 PNG 输出路径（默认写入 state-dir/auth-qr.png，传 '-' 禁用）")
	fs.BoolVar(&c.AcceptRoutes, "accept-routes", true, "接受其他节点通告的子网路由")
	fs.StringVar(&c.ExitNode, "exit-node", "", "使用指定 exit node（节点名或 IP），所有出站流量经其转发")
	fs.BoolVar(&c.ExitNodeAllowLAN, "exit-node-allow-lan-access", false, "使用 exit node 时仍允许访问本机所在局域网")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if c.SOCKS5Addr == "" && c.HTTPAddr == "" {
		return nil, fmt.Errorf("必须至少开启一种代理：-socks5 或 -http 不能同时为空")
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
