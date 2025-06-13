package casdoor_auth_plugin


import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config 插件配置结构
type Config struct {
	CasdoorEndpoint  string `json:"casdoorEndpoint"`  // Casdoor服务地址
	ApplicationName  string `json:"applicationName"`  // Casdoor应用名称
	OrganizationName string `json:"organizationName"` // Casdoor组织名称
	ClientId         string `json:"clientId"`         // OAuth2客户端ID
	ClientSecret     string `json:"clientSecret"`     // OAuth2客户端密钥
	RedirectPath     string `json:"redirectPath"`     // 回调路径，默认为 /callback
	CookieName       string `json:"cookieName"`       // Session Cookie名称，默认为 casdoor_session
	CookieDomain     string `json:"cookieDomain"`     // Cookie域名
	CookieSecure     bool   `json:"cookieSecure"`     // Cookie安全标志
	CookieMaxAge     int    `json:"cookieMaxAge"`     // Cookie过期时间（秒），默认24小时
	ExcludePaths     []string `json:"excludePaths"`   // 排除认证的路径
}

// CreateConfig 创建默认配置
func CreateConfig() *Config {
	return &Config{
		RedirectPath: "/callback",
		CookieName:   "casdoor_session",
		CookieMaxAge: 86400, // 24小时
		CookieSecure: true,
		ExcludePaths: []string{},
	}
}

// CasdoorAuth 插件主结构
type CasdoorAuth struct {
	next   http.Handler
	config *Config
	name   string
}

// New 创建插件实例
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.CasdoorEndpoint == "" {
		return nil, fmt.Errorf("casdoorEndpoint is required")
	}
	if config.ClientId == "" {
		return nil, fmt.Errorf("clientId is required")
	}
	if config.ClientSecret == "" {
		return nil, fmt.Errorf("clientSecret is required")
	}
	if config.ApplicationName == "" {
		return nil, fmt.Errorf("applicationName is required")
	}
	if config.OrganizationName == "" {
		return nil, fmt.Errorf("organizationName is required")
	}

	return &CasdoorAuth{
		next:   next,
		config: config,
		name:   name,
	}, nil
}

// ServeHTTP 处理HTTP请求
func (c *CasdoorAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// 检查是否为排除路径
	if c.isExcludedPath(req.URL.Path) {
		c.next.ServeHTTP(rw, req)
		return
	}

	// 检查是否为回调路径
	if req.URL.Path == c.config.RedirectPath {
		c.handleCallback(rw, req)
		return
	}

	// 检查是否已认证
	if c.isAuthenticated(req) {
		c.next.ServeHTTP(rw, req)
		return
	}

	// 重定向到Casdoor登录页面
	c.redirectToLogin(rw, req)
}

// isExcludedPath 检查是否为排除路径
func (c *CasdoorAuth) isExcludedPath(path string) bool {
	for _, excludePath := range c.config.ExcludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

// isAuthenticated 检查用户是否已认证
func (c *CasdoorAuth) isAuthenticated(req *http.Request) bool {
	cookie, err := req.Cookie(c.config.CookieName)
	if err != nil {
		return false
	}

	// 验证token是否有效
	return c.validateToken(cookie.Value)
}

// validateToken 验证访问令牌
func (c *CasdoorAuth) validateToken(token string) bool {
	// 使用Casdoor的token introspection端点验证token
	introspectURL := fmt.Sprintf("%s/api/login/oauth/introspect", c.config.CasdoorEndpoint)

	// 准备请求数据
	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequest("POST", introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false
	}

	// 使用Basic认证 (ClientId:ClientSecret)
	req.SetBasicAuth(c.config.ClientId, c.config.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	// 解析响应
	var introspectResp struct {
		Active bool `json:"active"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&introspectResp); err != nil {
		return false
	}

	return introspectResp.Active
}

// redirectToLogin 重定向到登录页面
func (c *CasdoorAuth) redirectToLogin(rw http.ResponseWriter, req *http.Request) {
	// 生成state参数用于防CSRF
	state := c.generateState()

	// 构造重定向URL
	originalURL := req.URL.String()
	redirectURL := fmt.Sprintf("%s://%s%s", c.getScheme(req), req.Host, c.config.RedirectPath)

	// 构造Casdoor授权URL - 使用标准OAuth2授权端点
	authURL := fmt.Sprintf("%s/login/oauth/authorize", c.config.CasdoorEndpoint)
	params := url.Values{}
	params.Set("client_id", c.config.ClientId)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("scope", "read")
	params.Set("state", state)

	loginURL := fmt.Sprintf("%s?%s", authURL, params.Encode())

	// 设置状态cookie，包含原始URL
	stateCookie := &http.Cookie{
		Name:     "casdoor_state",
		Value:    fmt.Sprintf("%s|%s", state, originalURL),
		Path:     "/",
		Domain:   c.config.CookieDomain,
		Secure:   c.config.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10分钟
	}
	http.SetCookie(rw, stateCookie)

	// 重定向到登录页面
	http.Redirect(rw, req, loginURL, http.StatusTemporaryRedirect)
}

// handleCallback 处理回调请求
func (c *CasdoorAuth) handleCallback(rw http.ResponseWriter, req *http.Request) {
	// 获取授权码和状态参数
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")

	if code == "" {
		http.Error(rw, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// 验证状态参数
	stateCookie, err := req.Cookie("casdoor_state")
	if err != nil {
		http.Error(rw, "Missing state cookie", http.StatusBadRequest)
		return
	}

	stateParts := strings.Split(stateCookie.Value, "|")
	if len(stateParts) != 2 || stateParts[0] != state {
		http.Error(rw, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	originalURL := stateParts[1]

	// 交换访问令牌
	token, err := c.exchangeToken(code, req)
	if err != nil {
		http.Error(rw, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 设置认证cookie
	authCookie := &http.Cookie{
		Name:     c.config.CookieName,
		Value:    token,
		Path:     "/",
		Domain:   c.config.CookieDomain,
		Secure:   c.config.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   c.config.CookieMaxAge,
	}
	http.SetCookie(rw, authCookie)

	// 删除状态cookie
	deleteStateCookie := &http.Cookie{
		Name:     "casdoor_state",
		Value:    "",
		Path:     "/",
		Domain:   c.config.CookieDomain,
		Secure:   c.config.CookieSecure,
		HttpOnly: true,
		MaxAge:   -1,
	}
	http.SetCookie(rw, deleteStateCookie)

	// 重定向到原始URL
	http.Redirect(rw, req, originalURL, http.StatusTemporaryRedirect)
}

// exchangeToken 交换访问令牌
func (c *CasdoorAuth) exchangeToken(code string, req *http.Request) (string, error) {
	// 使用Casdoor的token端点
	tokenURL := fmt.Sprintf("%s/api/login/oauth/access_token", c.config.CasdoorEndpoint)
	redirectURL := fmt.Sprintf("%s://%s%s", c.getScheme(req), req.Host, c.config.RedirectPath)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", c.config.ClientId)
	data.Set("client_secret", c.config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(tokenURL, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

// generateState 生成随机状态字符串
func (c *CasdoorAuth) generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// getScheme 获取请求协议
func (c *CasdoorAuth) getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}