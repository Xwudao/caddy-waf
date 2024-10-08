package waf

import (
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type CaddyWaf struct {
	logger          *zap.Logger
	ArgsRule        []string
	UserAgentRule   []string
	PostRule        []string
	IpAllowRule     []string
	IpBlockRule     []string
	RateLimitBucket int
	RateLimitRate   float64
	rateLimit       *RateLimit
}

func init() {
	caddy.RegisterModule(&CaddyWaf{})
}

// CaddyModule returns the Caddy module information.
func (*CaddyWaf) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(CaddyWaf) },
	}
}

func (w *CaddyWaf) Provision(ctx caddy.Context) error {
	w.logger = ctx.Logger(w) // g.logger is a *zap.Logger
	w.rateLimit = NewRateLimit(w.logger, w.RateLimitBucket, w.RateLimitRate)
	return nil
}

func (w *CaddyWaf) Validate() error {
	w.logger.Info("Validate.")
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (w *CaddyWaf) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	remoteAddr := w.getRequestIP(r)

	//ip allow rule
	if w.detectIp(remoteAddr, false) {
		return next.ServeHTTP(rw, r)
	}

	if w.detectIp(remoteAddr, true) ||
		w.detectRequestArgs(r) ||
		w.detectRequestBody(r) ||
		w.detectUserAgent(r) {
		return w.redirectIntercept(rw)
	}

	if w.RateLimitBucket > 0 {
		if w.rateLimit.detect(remoteAddr, r) {
			return w.redirectIntercept(rw)
		}
	}

	return next.ServeHTTP(rw, r)
}

//func (w *CaddyWaf) getRemoteIp(r *http.Request) string {
//	// first use x-forwarded-for
//
//	i := strings.Index(r.RemoteAddr, ":")
//	if i < 1 {
//		return r.RemoteAddr
//	}
//	return r.RemoteAddr[:i]
//}

// getRequestIP 获取请求的 IP 地址
func (w *CaddyWaf) getRequestIP(r *http.Request) string {
	// 优先尝试从 X-Forwarded-For 头部获取 IP 地址
	ip := r.Header.Get("X-Forwarded-For")
	w.logger.Info("X-Forwarded-For: " + ip)
	if ip != "" {
		// X-Forwarded-For 可能包含多个 IP 地址，用逗号分隔，取第一个
		ips := strings.Split(ip, ",")
		ip = strings.TrimSpace(ips[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// 尝试从 X-Real-Ip 头部获取 IP 地址
	ip = r.Header.Get("X-Real-Ip")
	if ip != "" {
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// 如果没有发现代理头部，使用 RemoteAddr 字段作为备用方法
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}

	// 解析 IP 地址并确保它是 IPv4 地址
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	return parsedIP.String()
}

func (w *CaddyWaf) Start() error {
	w.logger.Info("App start.")
	return nil
}

func (w *CaddyWaf) Stop() error {
	w.logger.Info("App stop.")
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyWaf)(nil)
	_ caddy.Validator             = (*CaddyWaf)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWaf)(nil)
	_ caddy.App                   = (*CaddyWaf)(nil)
)
