// Command tsproxy 是一个基于 tsnet 的轻量 Tailscale 客户端，
// 对外提供 SOCKS5 / HTTP(S) 正向代理，供本机其他程序通过 Tailscale 网络访问资源。
//
// 用法：
//
//	tsproxy up                  启动代理（首次运行会引导你完成授权）
//	tsproxy status               查看当前节点状态
//	tsproxy logout                登出并清除本地节点身份
//	tsproxy version               打印版本信息
//
// 运行 `tsproxy up -h` 查看全部参数。
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
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`tsproxy — 基于 tsnet 的 Tailscale SOCKS5 / HTTP 代理网关

用法:
  tsproxy up [flags]       启动 Tailscale 节点 + 本地代理（首次运行会引导授权）
  tsproxy status [flags]   查看当前节点状态
  tsproxy logout [flags]   登出并清除本地节点身份（下次需重新授权）
  tsproxy version          打印版本信息

常用 flags（完整列表见 'tsproxy up -h'）:
  -hostname string   节点在 tailnet 中显示的名字（默认使用主机名）
  -socks5 string     SOCKS5 监听地址（默认 127.0.0.1:1055，留空禁用）
  -http string        HTTP/HTTPS 代理监听地址（默认 127.0.0.1:1056，留空禁用）
  -authkey string      预授权密钥，跳过交互式登录（也可用环境变量 TS_AUTHKEY）
  -socks5-user/-socks5-pass   为 SOCKS5 开启用户名密码认证
  -http-user/-http-pass       为 HTTP 代理开启 Basic Auth 认证
  -exit-node string     使用指定 exit node，所有出站流量经其转发
  -exit-node-allow-lan-access  使用 exit node 时仍允许访问本机所在局域网
  -qr-file string        授权二维码 PNG 保存路径（默认 state-dir/auth-qr.png）

示例:
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
		log.Fatalf("❌ 启动失败: %v", err)
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
			authNote = fmt.Sprintf("（认证: %s / ******）", s5.Auth.User)
		}
		fmt.Printf("🧦 SOCKS5 代理已就绪: socks5://%s %s\n", cfg.SOCKS5Addr, authNote)
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
			authNote = fmt.Sprintf("（认证: %s / ******）", hp.Auth.User)
		}
		fmt.Printf("🌐 HTTP/HTTPS 代理已就绪: http://%s %s\n", cfg.HTTPAddr, authNote)
	}

	fmt.Println()
	fmt.Println("按 Ctrl+C 停止代理并退出。")

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("❌ 代理服务出错: %v", err)
		}
	case <-ctx.Done():
		fmt.Println("\n👋 收到退出信号，正在关闭…")
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
		log.Fatalf("❌ 获取本地客户端失败: %v", err)
	}
	st, err := lc.Status(context.Background())
	if err != nil {
		log.Fatalf("❌ 获取状态失败（节点可能未启动过）: %v", err)
	}
	if st.BackendState != ipn.Running.String() {
		fmt.Printf("状态: %s（未在线，运行 'tsproxy up' 启动）\n", st.BackendState)
		return
	}
	fmt.Printf("状态: %s\n", st.BackendState)
	if st.Self != nil {
		fmt.Printf("节点名: %s\n", st.Self.HostName)
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
		log.Fatalf("❌ 获取本地客户端失败: %v", err)
	}
	if err := lc.Logout(context.Background()); err != nil {
		log.Fatalf("❌ 登出失败: %v", err)
	}
	fmt.Println("✅ 已登出。下次运行 'tsproxy up' 需要重新扫码/点击链接授权。")
}

// parseStateOnly 用于 status/logout 子命令：只需要 hostname/state-dir，复用同一套 flags。
func parseStateOnly(args []string) (*config.Config, error) {
	// status/logout 不强制要求代理地址非空，临时借用 config.Parse 后放宽校验。
	cfg, err := config.Parse(append(args, "-socks5=127.0.0.1:0"))
	return cfg, err
}
