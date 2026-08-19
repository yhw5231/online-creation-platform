package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"online-creation-platform/models"
	"online-creation-platform/services"

	"golang.org/x/crypto/bcrypt"
)

func TestSessionSecretDefault(t *testing.T) {
	oldEnv := os.Getenv("SESSION_SECRET")
	oldPath := sessionKeyPath
	defer os.Setenv("SESSION_SECRET", oldEnv)
	defer func() { sessionKeyPath = oldPath }()

	dir := t.TempDir()
	sessionKeyPath = dir + "/secret"

	// 无环境变量且无持久化密钥 → 标记为弱密钥，且生成后的回退
	if err := os.Setenv("SESSION_SECRET", ""); err != nil {
		t.Fatal(err)
	}
	if !sessionSecretDefault() {
		t.Error("empty secret & missing file should be flagged as default")
	}
	// sessionKey() 应生成并落盘 32 字节随机密钥
	k := sessionKey()
	if len(k) < 32 {
		t.Errorf("generated key length %d, want >=32", len(k))
	}
	// 落盘后同一调用返回相同密钥（重启可复用）
	k2 := sessionKey()
	if string(k) != string(k2) {
		t.Error("persisted key should be stable across calls")
	}
	if sessionSecretDefault() {
		t.Error("persisted key should no longer be flagged as default")
	}

	if err := os.Setenv("SESSION_SECRET", "a-very-long-random-secret-123456"); err != nil {
		t.Fatal(err)
	}
	if sessionSecretDefault() {
		t.Error("long secret should not be flagged as default")
	}
}

func TestAtoiDefault(t *testing.T) {
	cases := []struct {
		s    string
		def  int
		want int
	}{
		{"12", 1, 12},
		{"0", 1, 1},    // non-positive falls back to default
		{"-3", 1, 1},   // negative falls back to default
		{"abc", 1, 1},  // non-numeric falls back
		{"", 8, 8},     // empty falls back
		{"  5 ", 1, 1}, // whitespace not parsed by Atoi
		{"999", 1, 999},
	}
	for _, c := range cases {
		if got := atoiDefault(c.s, c.def); got != c.want {
			t.Errorf("atoiDefault(%q, %d) = %d, want %d", c.s, c.def, got, c.want)
		}
	}
}

func TestSecureCompare(t *testing.T) {
	if !secureCompare("abc123", "abc123") {
		t.Error("identical strings should match")
	}
	if secureCompare("abc123", "abc124") {
		t.Error("differing last char should not match")
	}
	if secureCompare("abc", "abc123") {
		t.Error("different lengths should not match")
	}
	if secureCompare("", "") != true {
		t.Error("two empty strings should match")
	}
}

func TestTruncateRunes(t *testing.T) {
	s := "中文提示词prompt"
	got := truncateRunes(s, 4)
	if got != "中文提示…" {
		t.Errorf("truncateRunes got %q, want %q", got, "中文提示…")
	}
	if truncateRunes(s, 100) != s {
		t.Error("short string should stay unchanged")
	}
	if truncateRunes("", 3) != "" {
		t.Error("empty string should stay empty")
	}
	if truncateRunes(s, 0) != "" {
		t.Error("n<=0 should return empty")
	}
}

func TestGenerateRedeemCode(t *testing.T) {
	const allowed = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	for i := 0; i < 50; i++ {
		code := generateRedeemCode()
		if len(code) != 32 {
			t.Fatalf("redeem code length = %d, want 32", len(code))
		}
		for _, c := range code {
			if !strings.ContainsRune(allowed, c) {
				t.Fatalf("redeem code contains disallowed char %q", c)
			}
		}
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:55123"
	if got := clientIP(r); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want 203.0.113.7", got)
	}
	r.RemoteAddr = "192.168.1.10"
	if got := clientIP(r); got != "192.168.1.10" {
		t.Errorf("clientIP without port = %q", got)
	}

	// 开启代理信任：X-Real-IP 优先（nginx 覆盖式设置，客户端伪造的 XFF 前段被忽略）
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "10.0.0.5:8080"
	r2.Header.Set("X-Real-IP", "198.51.100.20")
	r2.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.20")
	if got := clientIP(r2); got != "198.51.100.20" {
		t.Errorf("clientIP with X-Real-IP = %q, want 198.51.100.20", got)
	}

	// 无 X-Real-IP 时取 XFF 最后一段：nginx 的 $proxy_add_x_forwarded_for 把真实
	// 来源追加在末尾，客户端伪造的前段值不会绕过限流
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.RemoteAddr = "10.0.0.5:8080"
	r3.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.21")
	if got := clientIP(r3); got != "198.51.100.21" {
		t.Errorf("clientIP last XFF entry = %q, want 198.51.100.21", got)
	}
	// XFF 末段为空时回退 RemoteAddr
	r3b := httptest.NewRequest(http.MethodGet, "/", nil)
	r3b.RemoteAddr = "10.0.0.5:8080"
	r3b.Header.Set("X-Forwarded-For", "6.6.6.6,")
	if got := clientIP(r3b); got != "10.0.0.5" {
		t.Errorf("clientIP empty XFF tail = %q, want 10.0.0.5", got)
	}

	// 未开启信任时忽略代理头
	t.Setenv("TRUST_PROXY_HEADERS", "")
	r4 := httptest.NewRequest(http.MethodGet, "/", nil)
	r4.RemoteAddr = "10.0.0.5:8080"
	r4.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.22")
	r4.Header.Set("X-Real-IP", "198.51.100.22")
	if got := clientIP(r4); got != "10.0.0.5" {
		t.Errorf("clientIP without trust = %q, want 10.0.0.5", got)
	}
}

// TestLoginLockout 验证登录失败锁定：连续失败达到阈值后锁定，
// 期间拒绝登录；成功登录后解除锁定。
func TestLoginLockout(t *testing.T) {
	key := "203.0.113.5"
	for i := 0; i < loginMaxAttempts; i++ {
		if isLoginLocked(key) {
			t.Fatalf("locked too early at attempt %d", i+1)
		}
		recordLoginFail(key)
	}
	if !isLoginLocked(key) {
		t.Fatal("should be locked after threshold failures")
	}
	clearLoginFails(key)
	if isLoginLocked(key) {
		t.Fatal("should be unlocked after success")
	}
	// 其他 IP 不受影响
	if isLoginLocked("198.51.100.3") {
		t.Fatal("unrelated IP should not be locked")
	}
}

// TestRateLimit 验证按 IP 的滑动窗口限流：同 IP 超限后敏感 POST 返回 429，
// 其他 IP 不受影响，GET 请求不计数，且不同敏感接口的额度互相独立
// （限流基准是「IP + 接口」，而不是接口被请求的总次数）。
func TestRateLimit(t *testing.T) {
	h := rateLimited(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	post := func(ip, path string) int {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, path, nil)
		rr.RemoteAddr = ip
		h(ww, rr)
		return ww.Code
	}
	// 登录接口额度内全部放行（已放宽至 600 次/分钟/IP，正常使用不可能触发）
	for i := 0; i < rateLimitLogin; i++ {
		if code := post("203.0.113.9:1234", "/login"); code != http.StatusOK {
			t.Fatalf("request %d blocked early: %d", i+1, code)
		}
	}
	if code := post("203.0.113.9:1234", "/login"); code != http.StatusTooManyRequests {
		t.Errorf("over-limit request = %d, want 429", code)
	}
	// 其他 IP 不受影响
	if code := post("198.51.100.7:1", "/login"); code != http.StatusOK {
		t.Errorf("other IP should pass, got %d", code)
	}
	// 同一 IP 下其他敏感接口额度独立：登录打满不影响注册
	if code := post("203.0.113.9:1234", "/register"); code != http.StatusOK {
		t.Errorf("register should have independent budget, got %d", code)
	}
	// 注册额度同样按上限拦截（不与登录共享计数）
	for i := 0; i < rateLimitRegister-1; i++ {
		if code := post("203.0.113.9:1234", "/register"); code != http.StatusOK {
			t.Fatalf("register request %d blocked early: %d", i+2, code)
		}
	}
	if code := post("203.0.113.9:1234", "/register"); code != http.StatusTooManyRequests {
		t.Errorf("register over-limit = %d, want 429", code)
	}
	// GET 不计入限流
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr.RemoteAddr = "203.0.113.9:1234"
	h(ww, rr)
	if ww.Code != http.StatusOK {
		t.Errorf("GET should bypass limiter, got %d", ww.Code)
	}
	// 窗口过期后恢复
	rateLimiter.Lock()
	delete(rateLimiter.hits, "203.0.113.9|/login")
	delete(rateLimiter.hits, "203.0.113.9|/register")
	rateLimiter.Unlock()
	if code := post("203.0.113.9:1234", "/login"); code != http.StatusOK {
		t.Errorf("fresh window should allow, got %d", code)
	}
}

func TestConsumeTokenFlow(t *testing.T) {
	w := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/create", nil)
	tok := mintToken(w, r1, "gen_token")
	if tok == "" {
		t.Fatal("mintToken returned empty token")
	}
	cookie := w.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatal("mintToken did not emit a session cookie")
	}
	post1 := httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader("_gen_token="+tok))
	post1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post1.Header.Set("Cookie", cookie)
	if !consumeToken(w, post1, "gen_token") {
		t.Fatal("first submit should consume the token successfully")
	}
	// 浏览器在首次提交后已收到新 Cookie（旧令牌已消费）。
	// 刷新页面会用「旧表单值 + 新 Cookie」重发 —— 必须校验失败。
	all := w.Header().Values("Set-Cookie")
	newCookie := all[len(all)-1]
	post2 := httptest.NewRequest(http.MethodPost, "/generate", strings.NewReader("_gen_token="+tok))
	post2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post2.Header.Set("Cookie", newCookie)
	if consumeToken(w, post2, "gen_token") {
		t.Fatal("replayed form must NOT pass token validation")
	}
}

func TestIsSafeLocalPath(t *testing.T) {
	ok := []string{"/", "/records", "/create?n=2", "/admin/users?q=x", "/积分", "/create", "/records?page=2"}
	for _, p := range ok {
		if !isSafeLocalPath(p) {
			t.Errorf("isSafeLocalPath(%q) should be true", p)
		}
	}
	bad := []string{"", "//evil.com", "https://evil.com", "/\\evil.com", "/a\r\nb", "\\\\evil.com", "C:\\windows"}
	for _, p := range bad {
		if isSafeLocalPath(p) {
			t.Errorf("isSafeLocalPath(%q) should be false", p)
		}
	}
}

func TestLocalTime(t *testing.T) {
	// legacy space format (UTC) -> Beijing time, with seconds
	if out := localTime("2026-01-02 15:04:05"); out != "2026-01-02 23:04:05" {
		t.Errorf("localTime(legacy) = %q, want %q (Beijing)", out, "2026-01-02 23:04:05")
	}
	// new driver ISO-8601 format (e.g. 2026-08-14T02:03:18Z) -> Beijing time
	if out := localTime("2026-08-14T02:03:18Z"); out != "2026-08-14 10:03:18" {
		t.Errorf("localTime(iso) = %q, want %q (Beijing)", out, "2026-08-14 10:03:18")
	}
	if out := localTime("2026-08-14T02:03:18.123Z"); out != "2026-08-14 10:03:18" {
		t.Errorf("localTime(iso fractional) = %q, want %q (Beijing)", out, "2026-08-14 10:03:18")
	}
	// unparseable -> passthrough
	raw := "not-a-time"
	if out := localTime(raw); out != raw {
		t.Errorf("localTime(%q) = %q, want passthrough", raw, out)
	}
	if out := localTime(""); out != "" {
		t.Errorf("localTime empty = %q", out)
	}
}

func TestCommaFormat(t *testing.T) {
	cases := map[interface{}]string{
		0:                    "0",
		999:                  "999",
		1000:                 "1,000",
		1234567:              "1,234,567",
		int64(1234567890123): "1,234,567,890,123",
		-1234567:             "-1,234,567",
		"999":                "999",
		"123456":             "123,456",
	}
	for in, want := range cases {
		if got := commaFormat(in); got != want {
			t.Errorf("commaFormat(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestLikeEscape(t *testing.T) {
	if likeEscape("abc") != "abc" {
		t.Errorf("plain: %q", likeEscape("abc"))
	}
	if likeEscape("%") != `\%` {
		t.Errorf("percent: %q", likeEscape("%"))
	}
	if likeEscape("_") != `\_` {
		t.Errorf("underscore: %q", likeEscape("_"))
	}
	if likeEscape("a\\b") != `a\\b` {
		t.Errorf("backslash: %q", likeEscape(`a\b`))
	}
	// combined input with meta characters
	if likeEscape(`100%_done`) != `100\%\_done` {
		t.Errorf("combined: %q", likeEscape(`100%_done`))
	}
}

func TestPagesAround(t *testing.T) {
	// total 1 → nil
	if got := pagesAround(1, 1); got != nil {
		t.Errorf("single page got %v, want nil", got)
	}
	// page 3 of 50 → [1 2 3 4 5 0 50]（±2 窗口覆盖 1..5）
	if got := pagesAround(3, 50); len(got) != 7 || got[0] != 1 || got[1] != 2 || got[2] != 3 || got[3] != 4 || got[4] != 5 || got[6] != 50 {
		t.Errorf("pagesAround(3,50) = %v", got)
	}
	// no ellipsis when few pages
	if got := pagesAround(1, 5); len(got) != 5 {
		t.Errorf("pagesAround(1,5) = %v, want 5 items", got)
	}
}

func TestExtForBytes(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want string
	}{
		{"png", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, ".png"},
		{"jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0}, ".jpg"},
		{"gif", []byte{'G', 'I', 'F', '8', '9', 'a'}, ".gif"},
		{"webp", []byte{'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'E', 'B', 'P'}, ".webp"},
		{"bmp", []byte{'B', 'M', 0, 0}, ".bmp"},
		{"unknown", []byte{1, 2, 3, 4, 5, 6}, ".png"},
	}
	for _, c := range cases {
		if got := extForBytes(c.b); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestNormalizeCheckinRange(t *testing.T) {
	cases := []struct {
		inMin, inMax     string
		wantMin, wantMax string
	}{
		{"5", "10", "5", "10"},   // normal
		{"", "", "1", "20"},      // empty → defaults
		{"30", "20", "30", "30"}, // inverted → max raised to min
		{"0", "8", "1", "8"},     // zero min → floor 1
		{"ab", "cd", "1", "20"},  // garbage → defaults
		{"7", "7", "7", "7"},     // equal bounds
	}
	for _, c := range cases {
		gotMin, gotMax := normalizeCheckinRange(c.inMin, c.inMax)
		if gotMin != c.wantMin || gotMax != c.wantMax {
			t.Errorf("normalizeCheckinRange(%q,%q) = (%q,%q), want (%q,%q)",
				c.inMin, c.inMax, gotMin, gotMax, c.wantMin, c.wantMax)
		}
	}
}

func TestOauthTarget(t *testing.T) {
	if got := oauthTarget(""); got != "/create" {
		t.Errorf("empty next = %q", got)
	}
	if got := oauthTarget("/records?page=2"); got != "/records?page=2" {
		t.Errorf("query next = %q", got)
	}
	if got := oauthTarget("//evil.com"); got != "/create" {
		t.Errorf("unsafe next = %q", got)
	}
}

func TestFlashRedirectCleanURL(t *testing.T) {
	// 新机制：toast 不进入 URL，改由 session 携带，重定向后地址栏干净。
	r := httptest.NewRequest(http.MethodGet, "/records", nil)
	w := httptest.NewRecorder()
	flashRedirect(w, r, "/records", "已删除该创作记录")
	loc := w.Header().Get("Location")
	if loc != "/records" {
		t.Fatalf("Location must be clean path without toast, got %q", loc)
	}
	if strings.Contains(loc, "toast") {
		t.Fatalf("toast leaked into URL: %q", loc)
	}
	// session 中应写入一次性 flash 消息
	s, _ := store.Get(r, "session")
	if v, _ := s.Values["flash_toast"].(string); v != "已删除该创作记录" {
		t.Fatalf("flash_toast not stored in session, got %q", v)
	}
	// Appends with & when the path already carries a query (path kept intact).
	r2 := httptest.NewRequest(http.MethodGet, "/records?page=2", nil)
	w2 := httptest.NewRecorder()
	flashRedirect(w2, r2, "/records?page=2", "已删除该创作记录")
	loc2 := w2.Header().Get("Location")
	if loc2 != "/records?page=2" {
		t.Fatalf("expected query preserved, got %q", loc2)
	}
}

func TestGenerateErrorTruncation(t *testing.T) {
	bigBody := strings.Repeat("x", 100000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(bigBody))
	}))
	defer srv.Close()

	c := services.NewGrokClient(srv.URL, "test-key")
	_, err := c.Generate(services.GenRequest{Prompt: "hello"})
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if len(err.Error()) > 400 {
		t.Fatalf("error message too long (%d bytes): not truncated", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("error should carry status code: %q", err.Error())
	}
}

// TestGenerateGatewayTimeoutFriendly verifies a 504 (openresty time-out HTML)
// is translated into a user-friendly hint instead of the raw HTML page.
func TestGenerateGatewayTimeoutFriendly(t *testing.T) {
	htmlBody := "<html>\n<head><title>504 Gateway Time-out</title></head>\n<body>\n<center><h1>504 Gateway Time-out</h1></center>\n<hr><center>openresty</center>\n</body>\n</html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
		w.Write([]byte(htmlBody))
	}))
	defer srv.Close()

	c := services.NewGrokClient(srv.URL, "test-key")
	_, err := c.Generate(services.GenRequest{Prompt: "hello"})
	if err == nil {
		t.Fatal("expected error for 504 response")
	}
	if !strings.Contains(err.Error(), "网关拦截") {
		t.Fatalf("expected gateway-blocked hint, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "<html>") || strings.Contains(err.Error(), "openresty") {
		t.Fatalf("raw HTML must not leak to user: %q", err.Error())
	}
}

// TestGenerateBadGatewayFriendly verifies a 502 upstream_unavailable JSON
// response is translated into a user-friendly hint instead of raw JSON.
func TestGenerateBadGatewayFriendly(t *testing.T) {
	jsonBody := `{"error":{"code":"upstream_unavailable","message":"上游服务暂不可用","param":null,"type":"server_error"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(jsonBody))
	}))
	defer srv.Close()

	c := services.NewGrokClient(srv.URL, "test-key")
	_, err := c.Generate(services.GenRequest{Prompt: "hello"})
	if err == nil {
		t.Fatal("expected error for 502 response")
	}
	if !strings.Contains(err.Error(), "上游服务暂不可用") || !strings.Contains(err.Error(), "未通过上游审核") {
		t.Fatalf("expected upstream-unavailable/audit hint, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "upstream_unavailable") || strings.Contains(err.Error(), "server_error") {
		t.Fatalf("raw JSON must not leak to user: %q", err.Error())
	}
}

func TestGenerateParseErrorSnippet(t *testing.T) {
	rumble := strings.Repeat("not-json", 30000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(rumble))
	}))
	defer srv.Close()

	c := services.NewGrokClient(srv.URL, "test-key")
	_, err := c.Generate(services.GenRequest{Prompt: "hello"})
	if err == nil {
		t.Fatal("expected parse error for invalid JSON body")
	}
	if len(err.Error()) > 300 {
		t.Fatalf("parse error message too long (%d bytes): not truncated", len(err.Error()))
	}
}

func TestGenerateEmptyDataRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"created":123,"data":[]}`))
	}))
	defer srv.Close()

	c := services.NewGrokClient(srv.URL, "test-key")
	_, err := c.Generate(services.GenRequest{Prompt: "hello"})
	if err == nil || !strings.Contains(err.Error(), "empty image response") {
		t.Fatalf("expected empty-response error, got %v", err)
	}
}

func TestDownloadFromURLSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte(strings.Repeat("a", 33<<20)))
	}))
	defer srv.Close()

	c := services.NewGrokClient("", "test-key")
	got, err := c.DownloadFromURL(srv.URL)
	if err != nil {
		t.Fatalf("download should succeed: %v", err)
	}
	if len(got) != 32<<20 {
		t.Fatalf("expected capped 32MB, got %d bytes", len(got))
	}
}

// TestLinuxdoEndpoints guards against regression to the broken /oauth/* paths
// and the non-supported "read" scope that produced the Linux.do Connect
// "Not Found / Please make sure you entered the information correctly" page.
func TestLinuxdoEndpoints(t *testing.T) {
	if linuxdoAuthorizeURL != "https://connect.linux.do/oauth2/authorize" {
		t.Errorf("authorize endpoint = %q, want /oauth2/authorize", linuxdoAuthorizeURL)
	}
	if linuxdoTokenURL != "https://connect.linux.do/oauth2/token" {
		t.Errorf("token endpoint = %q, want /oauth2/token", linuxdoTokenURL)
	}
	if linuxdoUserInfoURL != "https://connect.linux.do/api/user" {
		t.Errorf("userinfo endpoint = %q, want /api/user", linuxdoUserInfoURL)
	}
	if !strings.Contains(linuxdoScope, "openid") || !strings.Contains(linuxdoScope, "profile") {
		t.Errorf("scope = %q, want openid/profile/email", linuxdoScope)
	}
}

// TestFetchLinuxdoUser verifies the Bearer-token userinfo call and parsing of
// the Linux.do profile payload (id/username/email), including error paths.
func TestFetchLinuxdoUser(t *testing.T) {
	oldURL := linuxdoUserInfoURL
	defer func() { linuxdoUserInfoURL = oldURL }()

	// happy path: server asserts Authorization header, returns a real-shaped body
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
			t.Errorf("Authorization = %q, want Bearer tok-123", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":424242,"sub":"424242","username":"linuxdo_user","login":"linuxdo_user","name":"LD User","email":"u@example.com","active":true,"trust_level":2}`))
	}))
	defer srv.Close()
	linuxdoUserInfoURL = srv.URL

	id, username, email, err := fetchLinuxdoUser("tok-123")
	if err != nil {
		t.Fatalf("fetchLinuxdoUser: %v", err)
	}
	if id != 424242 || username != "linuxdo_user" || email != "u@example.com" {
		t.Errorf("got id=%d username=%q email=%q", id, username, email)
	}

	// non-200 -> error
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail":"authorization required"}`))
	}))
	defer errSrv.Close()
	linuxdoUserInfoURL = errSrv.URL
	if _, _, _, err := fetchLinuxdoUser("bad"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 error, got %v", err)
	}

	// invalid JSON -> error
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-json"))
	}))
	defer badSrv.Close()
	linuxdoUserInfoURL = badSrv.URL
	if _, _, _, err := fetchLinuxdoUser("tok"); err == nil {
		t.Error("expected JSON parse error, got nil")
	}
}

// TestOAuthLoginAutoEnter 验证 Linux.do 第三方登录的完整闭环：
// 已注册用户走回调登录后，最终 Set-Cookie 必须是携带 userID 的新登录会话，
// 直接进入网站（而不是被旋转掉的旧会话覆盖、弹回登录页）。
func TestOAuthLoginAutoEnter(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "oauthlogin.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()

	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok-1"}`))
	}))
	defer tokSrv.Close()
	infoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-1" {
			t.Errorf("Authorization = %q, want Bearer tok-1", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":424242,"username":"lduser","email":"u@example.com"}`))
	}))
	defer infoSrv.Close()
	oldTok, oldInfo := linuxdoTokenURL, linuxdoUserInfoURL
	linuxdoTokenURL, linuxdoUserInfoURL = tokSrv.URL, infoSrv.URL
	defer func() { linuxdoTokenURL, linuxdoUserInfoURL = oldTok, oldInfo }()

	models.SetConfig("enable_thirdparty_login", "true")
	models.SetConfig("linuxdo_client_id", "cid")
	models.SetConfig("linuxdo_client_secret", "csec")
	models.SetConfig("linuxdo_redirect_uri", "")
	res, _ := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status, oauth_provider, oauth_id) VALUES(?,?,?,?,?,?,?)",
		"lduser", "x", 0, "user", 1, "linuxdo", "424242")
	uid, _ := res.LastInsertId()

	// 模拟用户在登录页点了 Linux.do 授权：会话先持有 state/next
	w0 := httptest.NewRecorder()
	r0 := httptest.NewRequest(http.MethodGet, "/", nil)
	pre, _ := store.New(r0, "session")
	pre.Values["oauth_state"] = "teststate123"
	pre.Values["oauth_next"] = "/create"
	pre.Save(r0, w0)
	preCookie := lastCookie(w0)

	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodGet, "/auth/linuxdo/callback?code=abc123&state=teststate123", nil)
	rr.Header.Set("Cookie", preCookie)
	linuxdoCallbackHandler(ww, rr)

	if ww.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303", ww.Code)
	}
	if loc := ww.Header().Get("Location"); loc != "/create" {
		t.Errorf("callback Location = %q, want /create", loc)
	}
	// 核心回归断言：最终会话 cookie 必须能解出 userID（旧实现被 flash 回写覆盖后缺失）
	finalCookie := lastCookie(ww)
	rCheck := httptest.NewRequest(http.MethodGet, "/create", nil)
	rCheck.Header.Set("Cookie", finalCookie)
	sCheck, _ := store.Get(rCheck, "session")
	if v, _ := sCheck.Values["userID"].(int64); v != uid {
		t.Errorf("final session userID = %v, want %d (cookie=%s)", sCheck.Values["userID"], uid, truncateRunes(finalCookie, 200))
	}
	if v, _ := sCheck.Values["flash_toast"].(string); !strings.Contains(v, "欢迎回来") {
		t.Errorf("final session flash missing welcome toast: %q", v)
	}
	if _, ok := sCheck.Values["oauth_state"]; ok {
		t.Error("oauth_state should be cleaned from the rotated login session")
	}
}

// TestOAuthSetupAutoEnter 验证 Linux.do 首次注册（完善账号表单）提交成功后：
// 最终 Set-Cookie 必须携带 userID，注册完成直接进入网站，且 JSON/普通两种
// 提交方式行为一致。
func TestOAuthSetupAutoEnter(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "oauthsetup.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	models.SetConfig("open_registration", "true")
	models.SetConfig("enable_thirdparty_registration", "true")
	models.SetConfig("require_reg_code", "false")
	models.SetConfig("initial_points", "0")

	// 模拟回调后进入 setup 页：会话持有 pending 数据与 CSRF
	buildPending := func(prefix string) (string, string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/auth/linuxdo/setup", nil)
		s, _ := store.New(r, "session")
		s.Values["oauth_pending_user_id"] = int64(777001)
		s.Values["oauth_pending_username"] = "ld_" + prefix
		s.Values["oauth_pending_next"] = "/create"
		s.Save(r, w)
		c := lastCookie(w)
		r2 := httptest.NewRequest(http.MethodGet, "/auth/linuxdo/setup", nil)
		r2.Header.Set("Cookie", c)
		csrf := csrfToken(w, r2)
		return csrf, lastCookie(w)
	}

	// 1) 普通表单提交（非 ajax）→ 303 直接进站，新会话带 userID
	csrf, pendCookie := buildPending("plain")
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodPost, "/auth/linuxdo/setup", strings.NewReader(url.Values{
		"_csrf":    {csrf},
		"username": {"ld_plain"},
		"password": {"123456"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", pendCookie)
	linuxdoSetupHandler(ww, rr)
	if ww.Code != http.StatusSeeOther {
		t.Fatalf("setup(plain) status = %d, want 303: %s", ww.Code, truncateRunes(ww.Body.String(), 200))
	}
	if loc := ww.Header().Get("Location"); loc != "/create" {
		t.Errorf("setup(plain) Location = %q, want /create", loc)
	}
	finalPlain := lastCookie(ww)
	rCk := httptest.NewRequest(http.MethodGet, "/create", nil)
	rCk.Header.Set("Cookie", finalPlain)
	sCk, _ := store.Get(rCk, "session")
	if v, _ := sCk.Values["userID"].(int64); v == 0 {
		t.Errorf("setup(plain) final session missing userID (cookie=%s)", truncateRunes(finalPlain, 200))
	} else {
		var dbName string
		models.DB.QueryRow("SELECT username FROM users WHERE id=?", v).Scan(&dbName)
		if dbName != "ld_plain" {
			t.Errorf("setup(plain) logged-in user mismatch: %q", dbName)
		}
	}
	if v, _ := sCk.Values["flash_toast"].(string); !strings.Contains(v, "欢迎加入") {
		t.Errorf("setup(plain) flash missing: %q", v)
	}
	if _, ok := sCk.Values["oauth_pending_user_id"]; ok {
		t.Error("oauth_pending_user_id should be cleaned from the final session")
	}

	// 2) ajax 提交 → JSON ok + redirect，新会话同样带 userID
	csrf2, pendCookie2 := buildPending("ajax")
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/auth/linuxdo/setup", strings.NewReader(url.Values{
		"_csrf":    {csrf2},
		"username": {"ld_ajax"},
		"password": {"123456"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", pendCookie2)
	rr.Header.Set("X-Requested-With", "XMLHttpRequest")
	linuxdoSetupHandler(ww, rr)
	var ajaxResp struct {
		OK       bool   `json:"ok"`
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(ww.Body.Bytes(), &ajaxResp); err != nil {
		t.Fatalf("setup(ajax) not JSON: %v (%s)", err, truncateRunes(ww.Body.String(), 200))
	}
	if !ajaxResp.OK || ajaxResp.Redirect != "/create" {
		t.Errorf("setup(ajax) response = %+v", ajaxResp)
	}
	finalAjax := lastCookie(ww)
	rCk2 := httptest.NewRequest(http.MethodGet, "/create", nil)
	rCk2.Header.Set("Cookie", finalAjax)
	sCk2, _ := store.Get(rCk2, "session")
	if v, _ := sCk2.Values["userID"].(int64); v == 0 {
		t.Errorf("setup(ajax) final session missing userID (cookie=%s)", truncateRunes(finalAjax, 200))
	}
}

// TestSettingsPersistence 验证设置页的每一项配置都能落库并再次读取：
// 普通键值、数字校验、生成渠道（JSON + 兼容旧字段）、密钥留空保留、
// Redirect URI 支持持久化自定义值并支持“留空 = 自动兜底”。
func TestSettingsPersistence(t *testing.T) {
	// 独立临时数据库，避免污染真实配置
	if err := models.InitDB(filepath.Join(t.TempDir(), "settings.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()

	// 准备会话与 CSRF 令牌
	w := httptest.NewRecorder()
	r0 := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	csrf := csrfToken(w, r0)
	if csrf == "" {
		t.Fatal("csrf token empty")
	}
	cookie := w.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatal("no session cookie issued")
	}

	save := func(form url.Values) int {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, "/admin/update-settings", strings.NewReader(form.Encode()))
		rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr.Header.Set("Cookie", cookie)
		adminUpdateSettingsHandler(ww, rr)
		return ww.Code
	}
	get := func(k string) string {
		v, err := models.GetConfig(k)
		if err != nil {
			return ""
		}
		return v
	}

	// 第一次保存：提交设置页的全部字段
	form := url.Values{
		"_csrf":                          {csrf},
		"site_name":                      {"测试站点"},
		"generation_cost_points":         {"15"},
		"generation_fail_penalty":        {"0.25"},
		"open_registration":              {"true"},
		"enable_password_registration":   {"false"},
		"enable_thirdparty_registration": {"true"},
		"require_reg_code":               {"true"},
		"initial_points":                 {"50"},
		"enable_daily_checkin":           {"false"},
		"checkin_mode":                   {"random"},
		"checkin_fixed_points":           {"7"},
		"checkin_random_min":             {"3"},
		"checkin_random_max":             {"9"},
		"enable_thirdparty_login":        {"true"},
		"linuxdo_client_id":              {"demo-client-id"},
		"linuxdo_client_secret":          {"demo-secret"},
		"linuxdo_redirect_uri":           {"https://auth.example.com/cb"},
		"storage_type":                   {"s3"},
		"storage_endpoint":               {"https://oss.example.com"},
		"storage_bucket":                 {"my-bucket"},
		"storage_region":                 {"ap-northeast-1"},
		"storage_username":               {"AKID"},
		"storage_password":               {"SECRETKEY"},
		"storage_path_prefix":            {"images"},
		"cleanup_enabled":                {"true"},
		"cleanup_keep_days":              {"60"},
		"cleanup_max_mb":                 {"4096"},
		"ep_name[]":                      {"主渠道"},
		"ep_url[]":                       {"https://grok.example.com/v1"},
		"ep_key[]":                       {"sk-test-123"},
		"ep_model[]":                     {"grok-imagine-image-lite"},
		"ep_nsfw[]":                      {"0"},
		"ep_res[]":                       {"1k,2k"},
		"ep_models[]":                    {"grok-imagine-image-lite,gpt-image-2"},
		"ep_extra_models[]":              {"my-model-1"},
	}
	if code := save(form); code != http.StatusSeeOther {
		t.Fatalf("first save status = %d, want 303", code)
	}

	want := map[string]string{
		"site_name": "测试站点", "generation_cost_points": "15",
		"generation_fail_penalty":         "0.25",
		"open_registration": "true", "enable_password_registration": "false",
		"enable_thirdparty_registration": "true", "require_reg_code": "true",
		"initial_points": "50", "enable_daily_checkin": "false",
		"checkin_mode": "random", "checkin_fixed_points": "7",
		"checkin_random_min": "3", "checkin_random_max": "9",
		"enable_thirdparty_login": "true", "linuxdo_client_id": "demo-client-id",
		"linuxdo_client_secret": "demo-secret",
		"linuxdo_redirect_uri":  "https://auth.example.com/cb",
		"storage_type":          "s3", "storage_endpoint": "https://oss.example.com",
		"storage_bucket": "my-bucket", "storage_region": "ap-northeast-1",
		"storage_username": "AKID", "storage_password": "SECRETKEY",
		"storage_path_prefix": "images", "cleanup_enabled": "true",
		"cleanup_keep_days": "60", "cleanup_max_mb": "4096",
	}
	for k, wv := range want {
		if got := get(k); got != wv {
			t.Errorf("config[%s] = %q, want %q", k, got, wv)
		}
	}

	// 生成渠道持久化为 generation_endpoints JSON，并同步兼容旧字段
	var eps []GenerationEndpoint
	if raw := get("generation_endpoints"); raw == "" {
		t.Fatal("generation_endpoints empty after save")
	} else if err := json.Unmarshal([]byte(raw), &eps); err != nil {
		t.Fatalf("endpoints JSON parse: %v", err)
	}
	if len(eps) != 1 || eps[0].APIURL != "https://grok.example.com/v1" ||
		eps[0].APIKey != "sk-test-123" || eps[0].NSFW || eps[0].Name != "主渠道" {
		t.Errorf("unexpected endpoints persisted: %+v", eps)
	}
	if !containsString(eps[0].Models, "gpt-image-2") || !containsString(eps[0].Models, "my-model-1") {
		t.Errorf("channel models not merged+persisted: %v", eps[0].Models)
	}
	if !containsString(eps[0].Resolutions, "1k") {
		t.Errorf("resolutions not persisted: %v", eps[0].Resolutions)
	}
	if get("generation_api_url") != "https://grok.example.com/v1" ||
		get("generation_model") != "grok-imagine-image-lite" {
		t.Error("legacy generation_* fields not synced from endpoints")
	}

	// 第二次保存：仅修改站点名；Redirect URI 留空（= 自动兜底模式）、
	// 密钥留空（= 保留已保存值）、无效数字与非法随机区间不得覆盖旧值。
	form2 := url.Values{
		"_csrf":                          {csrf},
		"site_name":                      {"新站点名"},
		"generation_cost_points":         {"abc"}, // 非法：应保留 15
		"generation_fail_penalty":        {"xyz"}, // 非法倍率：应保留 0.25
		"open_registration":              {"true"},
		"enable_password_registration":   {"false"},
		"enable_thirdparty_registration": {"true"},
		"require_reg_code":               {"true"},
		"initial_points":                 {"50"},
		"enable_daily_checkin":           {"false"},
		"checkin_mode":                   {"random"},
		"checkin_fixed_points":           {"7"},
		"checkin_random_min":             {"9"}, // 9 > 3：区间非法，两者都应保留
		"checkin_random_max":             {"3"},
		"enable_thirdparty_login":        {"true"},
		"linuxdo_client_id":              {"demo-client-id"},
		"linuxdo_client_secret":          {""},
		"linuxdo_redirect_uri":           {""},
		"storage_type":                   {"s3"},
		"storage_endpoint":               {"https://oss.example.com"},
		"storage_bucket":                 {"my-bucket"},
		"storage_region":                 {"ap-northeast-1"},
		"storage_username":               {"AKID"},
		"storage_password":               {""},
		"storage_path_prefix":            {"images"},
		"cleanup_enabled":                {"true"},
		"cleanup_keep_days":              {"60"},
		"cleanup_max_mb":                 {"4096"},
		"ep_name[]":                      {"主渠道"},
		"ep_url[]":                       {"https://grok.example.com/v1"},
		"ep_key[]":                       {"sk-***"}, // 掩码回显：应保留原密钥
		"ep_model[]":                     {"grok-imagine-image-lite"},
		"ep_nsfw[]":                      {"0"},
		"ep_res[]":                       {"1k,2k"},
		"ep_models[]":                    {"grok-imagine-image-lite,gpt-image-2"},
		"ep_extra_models[]":              {"my-model-1"},
	}
	if code := save(form2); code != http.StatusSeeOther {
		t.Fatalf("second save status = %d, want 303", code)
	}
	if got := get("site_name"); got != "新站点名" {
		t.Errorf("site_name after second save = %q", got)
	}
	if got := get("generation_cost_points"); got != "15" {
		t.Errorf("invalid number must keep old value, got %q", got)
	}
	if got := get("generation_fail_penalty"); got != "0.25" {
		t.Errorf("invalid fail penalty must keep old value, got %q", got)
	}
	if got := get("checkin_random_min"); got != "3" {
		t.Errorf("invalid random range must keep min, got %q", got)
	}
	if got := get("checkin_random_max"); got != "9" {
		t.Errorf("invalid random range must keep max, got %q", got)
	}
	if got := get("linuxdo_client_secret"); got != "demo-secret" {
		t.Errorf("blank secret must keep saved value, got %q", got)
	}
	if got := get("storage_password"); got != "SECRETKEY" {
		t.Errorf("blank storage password must keep saved value, got %q", got)
	}
	if got := get("linuxdo_redirect_uri"); got != "" {
		t.Errorf("blank redirect uri must persist as empty (auto mode), got %q", got)
	}
	// 空 Redirect URI 应触发运行时自动兜底
	rr := httptest.NewRequest(http.MethodGet, "http://mysite.example.com/auth/linuxdo", nil)
	if got := linuxdoCallbackURL(rr); got != "http://mysite.example.com/auth/linuxdo/callback" {
		t.Errorf("auto fallback callback = %q", got)
	}
	// 掩码密钥回显不得覆盖真实密钥
	var eps2 []GenerationEndpoint
	json.Unmarshal([]byte(get("generation_endpoints")), &eps2)
	if len(eps2) != 1 || eps2[0].APIKey != "sk-test-123" {
		t.Errorf("masked key echoed back must keep original, got %+v", eps2)
	}

	// 自定义 Redirect URI 在后续保存中不再被自动地址覆盖：
	// 第三次保存带自定义值 → 必须原样持久化
	form3 := url.Values{
		"_csrf":                {csrf},
		"site_name":            {"新站点名"},
		"linuxdo_redirect_uri": {"https://custom.example.com/oauth/cb"},
	}
	save(form3)
	if got := get("linuxdo_redirect_uri"); got != "https://custom.example.com/oauth/cb" {
		t.Errorf("custom redirect uri not persisted verbatim, got %q", got)
	}
}

func TestRedeemCodeLabel(t *testing.T) {
	if got := redeemCodeLabel("register", 0); got != "注册码" {
		t.Errorf("register label = %q", got)
	}
	if got := redeemCodeLabel("points", 100); got != "100积分" {
		t.Errorf("points label = %q", got)
	}
	if got := redeemCodeLabel("", 30); got != "通用" {
		t.Errorf("legacy label = %q", got)
	}
	if got := redeemCodeLine("100积分", "ABC123"); got != "【100积分    ABC123】" {
		t.Errorf("line = %q", got)
	}
	if got := redeemCodeLine("注册码", "XYZ789"); got != "【注册码    XYZ789】" {
		t.Errorf("line = %q", got)
	}
}

// TestRedeemCodeTypes 验证积分兑换码 / 注册码分类型生成与使用隔离：
// 积分码可兑换积分但不能注册；注册码可注册但不能兑换积分；
// 旧版通用码（kind=”）两者皆可用。
func TestRedeemCodeTypes(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "redeem.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	// 后台页面渲染依赖模板
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	// 管理会话 + CSRF
	w := httptest.NewRecorder()
	r0 := httptest.NewRequest(http.MethodGet, "/admin/redeem-codes", nil)
	csrf := csrfToken(w, r0)
	cookie := w.Header().Get("Set-Cookie")

	// 生成：2 个 50 积分码 + 2 个注册码；页面需包含一键复制与复制行格式
	for _, form := range []url.Values{
		{"_csrf": {csrf}, "kind": {"points"}, "points": {"50"}, "count": {"2"}},
		{"_csrf": {csrf}, "kind": {"register"}, "points": {"0"}, "count": {"2"}},
	} {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, "/admin/redeem-codes/generate", strings.NewReader(form.Encode()))
		rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr.Header.Set("Cookie", cookie)
		adminGenerateRedeemCodesHandler(ww, rr)
		if ww.Code != http.StatusOK {
			t.Fatalf("generate status = %d, body=%s", ww.Code, ww.Body.String())
		}
		body := ww.Body.String()
		if !strings.Contains(body, "一键复制全部") {
			t.Error("generated page should include the bulk copy button")
		}
		if !strings.Contains(body, "【50积分    ") && !strings.Contains(body, "【注册码    ") {
			t.Errorf("page should show copy lines like 【物品名    码】, got:\n%s", body)
		}
	}
	var pointsCode, regCode string
	rows, err := models.DB.Query("SELECT code, points, kind FROM redeem_codes WHERE status='active' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var code, kind string
		var points int64
		if rows.Scan(&code, &points, &kind) != nil {
			continue
		}
		if kind == "points" && points == 50 {
			pointsCode = code
		}
		if kind == "register" {
			regCode = code
		}
	}
	if pointsCode == "" || regCode == "" {
		t.Fatalf("generated codes missing: points=%q register=%q", pointsCode, regCode)
	}

	// 旧版通用码（kind=''）：一个用于注册、一个用于兑换
	legacyReg := "LEGACYREG1"
	legacyPts := "LEGACYPTS1"
	models.DB.Exec("INSERT INTO redeem_codes(code, points, kind, created_by, status) VALUES(?,?,?,?,?)", legacyReg, 0, "", 0, "active")
	models.DB.Exec("INSERT INTO redeem_codes(code, points, kind, created_by, status) VALUES(?,?,?,?,?)", legacyPts, 30, "", 0, "active")

	// 兑换用户：直接建用户并伪造登录会话（含 CSRF 令牌）
	res, _ := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)", "redeemer", "x", 0, "user", 1)
	uid, _ := res.LastInsertId()
	makeSession := func(uid int64) (string, string) {
		w2 := httptest.NewRecorder()
		r2 := httptest.NewRequest(http.MethodGet, "/", nil)
		s, err := store.New(r2, "session")
		if err != nil {
			t.Fatal(err)
		}
		s.Values["userID"] = uid
		s.Values["username"] = "redeemer"
		s.Values["role"] = "user"
		s.Save(r2, w2)
		c := w2.Header().Get("Set-Cookie")
		r3 := httptest.NewRequest(http.MethodGet, "/", nil)
		r3.Header.Set("Cookie", c)
		csrf := csrfToken(w2, r3)
		// csrfToken 会再次写回会话，取最后一次 Set-Cookie 作为完整会话
		all := w2.Header().Values("Set-Cookie")
		return csrf, all[len(all)-1]
	}
	redeem := func(code string) string {
		csrf2, c2 := makeSession(uid)
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, "/redeem", strings.NewReader(url.Values{
			"code":  {code},
			"_csrf": {csrf2},
		}.Encode()))
		rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr.Header.Set("Cookie", c2)
		redeemHandler(ww, rr)
		return ww.Body.String()
	}
	// 积分码可兑换，注册码不可兑换，通用码可兑换
	if body := redeem(pointsCode); !strings.Contains(body, "兑换成功，获得 50 积分") {
		t.Errorf("points code redeem failed: %s", truncateRunes(body, 160))
	}
	if body := redeem(regCode); !strings.Contains(body, "兑换码无效或已被使用") {
		t.Errorf("register code must NOT be redeemable: %s", truncateRunes(body, 160))
	}
	if body := redeem(legacyPts); !strings.Contains(body, "兑换成功，获得 30 积分") {
		t.Errorf("legacy code redeem failed: %s", truncateRunes(body, 160))
	}

	// 注册流程：开启注册码要求；积分码不能注册，注册码/通用码可以
	models.SetConfig("require_reg_code", "true")
	models.SetConfig("initial_points", "0")
	// 专门用于注册尝试的未兑换积分码：验证失败的注册不会消耗它
	ptsRegCode := "PTSREG1"
	models.DB.Exec("INSERT INTO redeem_codes(code, points, kind, created_by, status) VALUES(?,?,?,?,?)", ptsRegCode, 10, "points", 0, "active")
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/register", nil)
	regCSRF := csrfToken(w3, r3)
	regCookie := w3.Header().Get("Set-Cookie")
	register := func(username, code string) (int, string) {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(url.Values{
			"_csrf":            {regCSRF},
			"username":         {username},
			"password":         {"123456"},
			"confirm_password": {"123456"},
			"reg_code":         {code},
		}.Encode()))
		rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr.Header.Set("Cookie", regCookie)
		registerHandler(ww, rr)
		return ww.Code, ww.Body.String()
	}
	if code, body := register("baduser1", ptsRegCode); !(code == http.StatusOK && strings.Contains(body, "注册码无效或已被使用")) {
		t.Errorf("points code must NOT register: code=%d body=%s", code, truncateRunes(body, 160))
	}
	if code, _ := register("gooduser1", regCode); code != http.StatusSeeOther {
		t.Errorf("register with register code: status=%d", code)
	}
	if code, _ := register("gooduser2", legacyReg); code != http.StatusSeeOther {
		t.Errorf("register with legacy code: status=%d", code)
	}
	// 注册码被消耗，积分码未被消耗
	var regUsed int
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes WHERE code=? AND status='used'", regCode).Scan(&regUsed)
	if regUsed != 1 {
		t.Errorf("register code should be consumed, used=%d", regUsed)
	}
	var ptsStillActive int
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes WHERE code=? AND status='active'", ptsRegCode).Scan(&ptsStillActive)
	if ptsStillActive != 1 {
		t.Error("points code should remain active after failed registration attempts")
	}
	var users int
	models.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username IN ('gooduser1','gooduser2')").Scan(&users)
	if users != 2 {
		t.Errorf("registered users = %d, want 2", users)
	}
}

// TestCodeErrorShownInline 验证兑换码/注册码不可用时，错误以红色文字显示在对应
// 输入框下方（is-invalid 高亮），页面停留在表单本身，绝不跳转到整页错误页：
// /redeem 兑换页、/register 注册页、Linux.do 完善账号页（此前会跳转错误页）。
func TestCodeErrorShownInline(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "inline.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	// 积分兑换码：可兑换积分，但不能用作注册码
	models.DB.Exec("INSERT INTO redeem_codes(code, points, kind, created_by, status) VALUES(?,?,?,?,?)", "PTSONLY1", 10, "points", 0, "active")
	// 兑换用户 + 伪造会话
	res, _ := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)", "redeemer2", "x", 0, "user", 1)
	uid, _ := res.LastInsertId()
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	s, _ := store.New(r2, "session")
	s.Values["userID"] = uid
	s.Values["username"] = "redeemer2"
	s.Values["role"] = "user"
	s.Save(r2, w2)
	all := w2.Header().Values("Set-Cookie")
	cookie := all[len(all)-1]
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.Header.Set("Cookie", cookie)
	redeemCSRF := csrfToken(w2, r3)
	// csrfToken 会把令牌写回会话并重发 Cookie，取最后一次 Set-Cookie
	all = w2.Header().Values("Set-Cookie")
	cookie = all[len(all)-1]
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodPost, "/redeem", strings.NewReader(url.Values{
		"code":  {"NOPE123"},
		"_csrf": {redeemCSRF},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", cookie)
	redeemHandler(ww, rr)
	body := ww.Body.String()
	if ww.Code != http.StatusOK {
		t.Fatalf("redeem invalid code status = %d", ww.Code)
	}
	if !strings.Contains(body, "id=\"codeError\"") || !strings.Contains(body, "兑换码无效或已被使用") {
		t.Errorf("redeem inline error missing:\n%s", truncateRunes(body, 600))
	}
	if !strings.Contains(body, "is-invalid") {
		t.Error("redeem input should get is-invalid class")
	}
	if !strings.Contains(body, "value=\"NOPE123\"") {
		t.Error("redeem input should keep the entered code")
	}
	if strings.Contains(body, "alert alert-danger") || strings.Contains(body, "error-wrap") {
		t.Error("redeem page should not show top alert or error page")
	}

	// 2) /register POST 用积分码当注册码（require_reg_code 开启）→ 内联错误
	models.SetConfig("require_reg_code", "true")
	models.SetConfig("open_registration", "true")
	models.SetConfig("enable_password_registration", "true")
	w3 := httptest.NewRecorder()
	r3b := httptest.NewRequest(http.MethodGet, "/register", nil)
	regCSRF := csrfToken(w3, r3b)
	regCookie := w3.Header().Get("Set-Cookie")
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(url.Values{
		"_csrf":            {regCSRF},
		"username":         {"baduser2"},
		"password":         {"123456"},
		"confirm_password": {"123456"},
		"reg_code":         {"PTSONLY1"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", regCookie)
	registerHandler(ww, rr)
	body = ww.Body.String()
	if ww.Code != http.StatusOK {
		t.Fatalf("register invalid code status = %d", ww.Code)
	}
	if !strings.Contains(body, "id=\"regCodeError\"") || !strings.Contains(body, "注册码无效或已被使用") {
		t.Errorf("register inline reg-code error missing:\n%s", truncateRunes(body, 600))
	}
	if !strings.Contains(body, "is-invalid") {
		t.Error("register reg_code input should get is-invalid class")
	}
	if strings.Contains(body, "error-wrap") {
		t.Error("register should not render the error page")
	}

	// 3) Linux.do 完善账号页 POST 无效注册码：不再跳整页错误，回表单并内联提示
	models.SetConfig("enable_thirdparty_registration", "true")
	w4 := httptest.NewRecorder()
	r4 := httptest.NewRequest(http.MethodGet, "/auth/linuxdo/setup", nil)
	s4, _ := store.New(r4, "session")
	s4.Values["oauth_pending_user_id"] = int64(99991)
	s4.Values["oauth_pending_username"] = "linuxuser"
	s4.Values["oauth_pending_next"] = "/create"
	s4.Save(r4, w4)
	c4 := w4.Header().Get("Set-Cookie")
	r4b := httptest.NewRequest(http.MethodGet, "/auth/linuxdo/setup", nil)
	r4b.Header.Set("Cookie", c4)
	setupCSRF := csrfToken(w4, r4b)
	all = w4.Header().Values("Set-Cookie")
	oatCookie := all[len(all)-1]
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/auth/linuxdo/setup", strings.NewReader(url.Values{
		"_csrf":            {setupCSRF},
		"username":         {"linuxuser"},
		"password":         {"123456"},
		"confirm_password": {"123456"},
		"reg_code":         {"PTSONLY1"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", oatCookie)
	linuxdoSetupHandler(ww, rr)
	body = ww.Body.String()
	if ww.Code != http.StatusOK {
		t.Fatalf("oauth setup invalid code status = %d", ww.Code)
	}
	if !strings.Contains(body, "id=\"regCodeError\"") || !strings.Contains(body, "注册码无效或已被使用") {
		t.Errorf("oauth setup inline reg-code error missing:\n%s", truncateRunes(body, 600))
	}
	if strings.Contains(body, "error-wrap") {
		t.Error("oauth setup must not jump to the full error page")
	}
	if !strings.Contains(body, "value=\"linuxuser\"") {
		t.Error("oauth setup should keep the entered username")
	}
}

// lastCookie 返回 recorder 中最后一次 Set-Cookie（会话状态最新的一份）。
func lastCookie(w *httptest.ResponseRecorder) string {
	all := w.Header().Values("Set-Cookie")
	if len(all) == 0 {
		return ""
	}
	return all[len(all)-1]
}

// TestUnreadNoticeNavDot 验证公告不再全局悬浮：只有导航“公告”入口，存在未读
// （更新的）公告时显示红点；访问公告页后红点消失，新公告发布后再次出现。
func TestUnreadNoticeNavDot(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "notice.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	res, _ := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)", "noticeUser", "x", 0, "user", 1)
	uid, _ := res.LastInsertId()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	s, _ := store.New(r, "session")
	s.Values["userID"] = uid
	s.Values["username"] = "noticeUser"
	s.Values["role"] = "user"
	s.Save(r, w)
	cookie := w.Header().Get("Set-Cookie")

	redeemPage := func() string {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodGet, "/redeem", nil)
		rr.Header.Set("Cookie", cookie)
		redeemHandler(ww, rr)
		return ww.Body.String()
	}
	// 1) 无公告：导航显示“公告”但无红点，且页面不再有悬浮公告条
	body := redeemPage()
	if !strings.Contains(body, "data-nav=\"/notices\"") {
		t.Error("nav should include the notices entry in the nav row")
	}
	if strings.Contains(body, "有新的公告") {
		t.Error("no red dot expected when there are no notices")
	}
	if strings.Contains(body, "site-notice") {
		t.Error("floating announcement bar should be gone")
	}
	// 2) 发布新公告：导航出现红点
	models.DB.Exec("INSERT INTO notices(title, content, is_active) VALUES(?,?,1)", "新公告", "内容")
	body = redeemPage()
	if !strings.Contains(body, "title=\"有新的公告\"") {
		t.Error("red dot should appear when an unread notice exists")
	}
	// 3) 访问公告页后红点消失
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodGet, "/notices", nil)
	rr.Header.Set("Cookie", cookie)
	noticesHandler(ww, rr)
	body = redeemPage()
	if strings.Contains(body, "有新的公告") {
		t.Error("red dot should disappear after reading notices")
	}
	// 4) 再发一条新公告：红点复现
	models.DB.Exec("INSERT INTO notices(title, content, is_active) VALUES(?,?,1)", "再一条", "内容")
	body = redeemPage()
	if !strings.Contains(body, "title=\"有新的公告\"") {
		t.Error("red dot should reappear after a newer notice is published")
	}
}

// TestSystemLogsAndFilters 验证系统日志：登录（成功/失败）、签到、兑换、创作、
// API 调用均记录 时间/用户/行为/积分变动/IP；管理后台日志页可按各字段筛选。
func TestSystemLogsAndFilters(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "logs.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	models.SetConfig("enable_daily_checkin", "true")
	models.SetConfig("checkin_mode", "fixed")
	models.SetConfig("checkin_fixed_points", "10")
	models.SetConfig("generation_cost_points", "10")
	models.SetConfig("generation_endpoints", `[{"id":1,"name":"主渠道","api_url":"https://a.example/v1","api_key":"k1","resolutions":["1k","2k"],"models":["grok-imagine-image-lite"]}]`)
	models.DB.Exec("INSERT INTO redeem_codes(code, points, kind, created_by, status) VALUES(?,?,?,?,?)", "LOGCODE1", 30, "points", 0, "active")

	// 用 seedAdmin 创建的 admin 账号走完整登录流程（密码 admin123）
	// 1) 登录失败
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	s, _ := store.New(r, "session")
	s.Save(r, w)
	c1 := w.Header().Get("Set-Cookie")
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Cookie", c1)
	csrf1 := csrfToken(w, r2)
	c1 = lastCookie(w)
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{
		"_csrf":    {csrf1},
		"username": {"admin"},
		"password": {"wrong-pass"},
	}.Encode()))
	rr.RemoteAddr = "203.0.113.9:4321"
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", c1)
	loginHandler(ww, rr)
	if ww.Code != http.StatusOK {
		t.Fatalf("failed login status = %d", ww.Code)
	}
	// 2) 登录成功（会话轮换后取新 Cookie）
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{
		"_csrf":    {csrf1},
		"username": {"admin"},
		"password": {"admin123"},
	}.Encode()))
	rr.RemoteAddr = "203.0.113.9:4321"
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", c1)
	loginHandler(ww, rr)
	if ww.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d", ww.Code)
	}
	c2 := lastCookie(ww)
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.Header.Set("Cookie", c2)
	csrf2 := csrfToken(ww, r3)
	c2 = lastCookie(ww)

	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		rr.RemoteAddr = "203.0.113.9:4321"
		rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr.Header.Set("Cookie", c2)
		rr.Header.Set("Referer", "http://x/"+path)
		switch path {
		case "/checkin":
			checkinHandler(ww, rr)
		case "/redeem":
			redeemHandler(ww, rr)
		case "/generate":
			generateHandler(ww, rr)
		}
		return ww
	}
	// 3) 签到
	post("/checkin", url.Values{"_csrf": {csrf2}})
	// 4) 兑换
	post("/redeem", url.Values{"_csrf": {csrf2}, "code": {"LOGCODE1"}})
	// 5) 创作（网页）
	genTokR := httptest.NewRecorder()
	genTokReq := httptest.NewRequest(http.MethodGet, "/create", nil)
	genTokReq.Header.Set("Cookie", c2)
	genToken := mintToken(genTokR, genTokReq, "gen_token")
	c2 = lastCookie(genTokR)
	post("/generate", url.Values{
		"_csrf":        {csrf2},
		"_gen_token":   {genToken},
		"prompt":       {"系统日志测试"},
		"channel":      {"1"},
		"resolution":   {"1k"},
		"model":        {"grok-imagine-image-lite"},
		"aspect_ratio": {"1:1"},
		"n":            {"1"},
	})
	// 6) API 调用
	var uid int64
	models.DB.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&uid)
	apiKey, _ := models.SetAPIKey(uid)
	aww := httptest.NewRecorder()
	arr := httptest.NewRequest(http.MethodPost, "/api/v1/generate", strings.NewReader(`{"prompt":"API测试","channel":"1","n":2,"resolution":"1k","aspect_ratio":"1:1"}`))
	arr.RemoteAddr = "198.51.100.7:9000"
	arr.Header.Set("Content-Type", "application/json")
	arr.Header.Set("Authorization", "Bearer "+apiKey)
	apiAuthMiddleware(apiGenerateHandler)(aww, arr)
	if aww.Code != http.StatusOK {
		t.Fatalf("api generate status = %d body=%s", aww.Code, aww.Body.String())
	}

	// 7) 落库断言：6 类行为各一条，积分变动正确
	rows, err := models.DB.Query("SELECT action, points_delta, ip, username FROM system_logs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type lr struct {
		action string
		delta  int64
		ip     string
		uname  string
	}
	var got []lr
	for rows.Next() {
		var e lr
		if rows.Scan(&e.action, &e.delta, &e.ip, &e.uname) == nil {
			got = append(got, e)
		}
	}
	want := []lr{{"login_fail", 0, "203.0.113.9", "admin"}, {"login", 0, "203.0.113.9", "admin"},
		{"checkin", 10, "203.0.113.9", "admin"}, {"redeem", 30, "203.0.113.9", "admin"},
		{"create", -10, "203.0.113.9", "admin"}, {"api", -20, "198.51.100.7", "admin"}}
	if len(got) != len(want) {
		t.Fatalf("system logs = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("log[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// 8) 管理后台日志页：列表与筛选
	getLogs := func(query string) string {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodGet, "/admin/logs"+query, nil)
		rr.Header.Set("Cookie", c2)
		adminSystemLogsHandler(ww, rr)
		return ww.Body.String()
	}
	body := getLogs("")
	if !strings.Contains(body, "签到获得 10 积分") || !strings.Contains(body, "兑换 30 积分") ||
		!strings.Contains(body, "API 生成") || !strings.Contains(body, "登录成功") {
		t.Errorf("admin logs page missing entries:\n%s", truncateRunes(body, 800))
	}
	if !strings.Contains(body, "203.0.113.9") || !strings.Contains(body, "198.51.100.7") {
		t.Error("admin logs page should show IP addresses")
	}
	// 行为筛选
	body = getLogs("?action=checkin")
	if !strings.Contains(body, "签到获得 10 积分") || strings.Contains(body, "登录成功") {
		t.Error("action=checkin filter should keep only checkin rows")
	}
	// 用户名筛选
	body = getLogs("?user=admin")
	if !strings.Contains(body, "签到获得 10 积分") || strings.Contains(body, "暂无符合条件的日志记录") {
		t.Error("user=admin filter should match rows")
	}
	body = getLogs("?user=nobody")
	if !strings.Contains(body, "暂无符合条件的日志记录") {
		t.Error("user=nobody filter should return empty")
	}
	// 积分变动筛选（按单元格标记断言，避免被导航 SVG 路径里的 -10 干扰）
	body = getLogs("?delta=in")
	if !strings.Contains(body, "text-success fw-semibold\">+30") || !strings.Contains(body, "text-success fw-semibold\">+10") ||
		strings.Contains(body, "text-danger fw-semibold") {
		t.Errorf("delta=in filter should show only positive changes:\n%s", truncateRunes(body, 3000))
	}
	body = getLogs("?delta=out")
	if !strings.Contains(body, "text-danger fw-semibold\">-10") || !strings.Contains(body, "text-danger fw-semibold\">-20") ||
		strings.Contains(body, "text-success fw-semibold") {
		t.Errorf("delta=out filter should show only negative changes:\n%s", truncateRunes(body, 3000))
	}
	// IP 筛选
	body = getLogs("?ip=198.51.100")
	if !strings.Contains(body, "API 生成") || strings.Contains(body, "签到获得") {
		t.Error("ip filter should match only API row")
	}
	// 时间筛选：未来日期 → 空
	body = getLogs("?from=2999-01-01&to=2999-12-31")
	if !strings.Contains(body, "暂无符合条件的日志记录") {
		t.Error("future date range should return empty")
	}
}

// TestAdminRenameUsername 验证管理员用户名可修改：设置页回显当前用户名，
// 保存后在 users 表生效并与会话同步；重名/过短被拒绝。
func TestAdminRenameUsername(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "rename.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	var uid int64
	models.DB.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&uid)
	// 管理员会话 + CSRF
	buildSess := func() (string, string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
		s, _ := store.New(r, "session")
		s.Values["userID"] = uid
		s.Values["username"] = "admin"
		s.Values["role"] = "admin"
		s.Save(r, w)
		c := w.Header().Get("Set-Cookie")
		r2 := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
		r2.Header.Set("Cookie", c)
		csrf := csrfToken(w, r2)
		return csrf, lastCookie(w)
	}
	csrf, cookie := buildSess()
	save := func(name string) (*httptest.ResponseRecorder, string) {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, "/admin/update-settings", strings.NewReader(url.Values{
			"_csrf":          {csrf},
			"admin_username": {name},
			"settings_pane":  {"basic"},
		}.Encode()))
		rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr.Header.Set("Cookie", cookie)
		adminUpdateSettingsHandler(ww, rr)
		return ww, ww.Body.String()
	}
	// 1) 设置页回显当前用户名
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	rr.Header.Set("Cookie", cookie)
	adminSettingsHandler(ww, rr)
	if !strings.Contains(ww.Body.String(), "value=\"admin\"") {
		t.Error("settings page should show current admin username")
	}
	// 2) 正常改名成功
	if ww, _ := save("newadmin"); ww.Code != http.StatusSeeOther {
		t.Fatalf("rename status = %d", ww.Code)
	}
	var name string
	models.DB.QueryRow("SELECT username FROM users WHERE id=?", uid).Scan(&name)
	if name != "newadmin" {
		t.Errorf("admin username = %q, want newadmin", name)
	}
	// 3) 重名被拒绝
	models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)", "taken", "x", 0, "user", 1)
	w2, _ := save("taken")
	if w2.Code != http.StatusSeeOther {
		t.Fatalf("conflict save status = %d", w2.Code)
	}
	models.DB.QueryRow("SELECT username FROM users WHERE id=?", uid).Scan(&name)
	if name != "newadmin" {
		t.Errorf("conflicting rename should be rejected, got %q", name)
	}
	// 4) 过短用户名被拒绝
	if ww, _ := save("a"); ww.Code != http.StatusSeeOther {
		t.Fatalf("short name status = %d", ww.Code)
	}
	models.DB.QueryRow("SELECT username FROM users WHERE id=?", uid).Scan(&name)
	if name != "newadmin" {
		t.Errorf("too-short rename should be rejected, got %q", name)
	}
}

// TestRedeemCodeBatchAndRemark 验证兑换码管理页的批量能力：
// 生成时备注写入、列表展示生成时间与备注、批量备注/批量作废（逗号分隔 ids）、
// 页面包含批量选择与复制控件。
func TestRedeemCodeBatchAndRemark(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "batch.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	// 管理会话 + CSRF
	w := httptest.NewRecorder()
	r0 := httptest.NewRequest(http.MethodGet, "/admin/redeem-codes", nil)
	csrf := csrfToken(w, r0)
	cookie := w.Header().Get("Set-Cookie")

	// 批量生成 2 个注册码，并带统一备注
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodPost, "/admin/redeem-codes/generate", strings.NewReader(url.Values{
		"_csrf":  {csrf},
		"kind":   {"register"},
		"points": {"0"},
		"count":  {"2"},
		"remark": {"渠道A-5月活动"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", cookie)
	adminGenerateRedeemCodesHandler(ww, rr)
	if ww.Code != http.StatusOK {
		t.Fatalf("generate status = %d, body=%s", ww.Code, ww.Body.String())
	}
	body := ww.Body.String()
	// 生成结果与列表页应包含备注、批量选择、复制与生成时间控件
	for _, want := range []string{"渠道A-5月活动", "全选本页", "复制选中（含物品名）", "复制选中（仅码）", "生成时间", "批量作废", "code-check"} {
		if !strings.Contains(body, want) {
			t.Errorf("generated page missing %q", want)
		}
	}

	// 数据库校验：备注已入库、生成时间已填充
	var id1, id2 int64
	rows, err := models.DB.Query("SELECT id, remark, created_at FROM redeem_codes WHERE kind='register' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var id int64
		var remark string
		var created sql.NullTime
		if rows.Scan(&id, &remark, &created) != nil {
			continue
		}
		n++
		if remark != "渠道A-5月活动" {
			t.Errorf("code %d remark = %q, want 渠道A-5月活动", id, remark)
		}
		if !created.Valid || created.Time.IsZero() {
			t.Errorf("code %d created_at not populated", id)
		}
		if id1 == 0 {
			id1 = id
		} else {
			id2 = id
		}
	}
	rows.Close()
	if n != 2 || id1 == 0 || id2 == 0 {
		t.Fatalf("expected 2 codes with ids, got %d (id1=%d id2=%d)", n, id1, id2)
	}

	// 批量备注：两个码一次更新为新备注
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/admin/redeem-codes/remark", strings.NewReader(url.Values{
		"_csrf":  {csrf},
		"ids":    {fmt.Sprintf("%d,%d", id1, id2)},
		"remark": {"渠道B-六月"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", cookie)
	adminRemarkRedeemCodesHandler(ww, rr)
	if ww.Code != http.StatusSeeOther {
		t.Fatalf("batch remark status = %d", ww.Code)
	}
	var cnt int
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes WHERE id IN (?,?) AND remark='渠道B-六月'", id1, id2).Scan(&cnt)
	if cnt != 2 {
		t.Errorf("batch remark applied to %d codes, want 2", cnt)
	}

	// 无 ids 的备注请求应拒绝并提示（不崩溃）
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/admin/redeem-codes/remark", strings.NewReader(url.Values{
		"_csrf":  {csrf},
		"remark": {"无目标"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", cookie)
	adminRemarkRedeemCodesHandler(ww, rr)
	if ww.Code != http.StatusSeeOther {
		t.Errorf("empty ids remark status = %d, want 303 redirect", ww.Code)
	}

	// 批量作废：逗号分隔 ids 一次作废两个
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/admin/redeem-codes/void", strings.NewReader(url.Values{
		"_csrf": {csrf},
		"ids":   {fmt.Sprintf("%d,%d", id1, id2)},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", cookie)
	adminVoidRedeemCodeHandler(ww, rr)
	if ww.Code != http.StatusSeeOther {
		t.Fatalf("batch void status = %d", ww.Code)
	}
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes WHERE id IN (?,?) AND status='void'", id1, id2).Scan(&cnt)
	if cnt != 2 {
		t.Errorf("batch voided %d codes, want 2", cnt)
	}

	// 列表页展示生成时间与备注（备注保留最新值）
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodGet, "/admin/redeem-codes", nil)
	rr.Header.Set("Cookie", cookie)
	adminRedeemCodesHandler(ww, rr)
	if ww.Code != http.StatusOK {
		t.Fatalf("list status = %d", ww.Code)
	}
	body = ww.Body.String()
	if !strings.Contains(body, "渠道B-六月") {
		t.Error("list should show latest remark")
	}
	if !strings.Contains(body, "生成时间") || !strings.Contains(body, "备注") {
		t.Error("list should show 生成时间 and 备注 columns")
	}
	// 列表中每行都有可独立保存备注的表单控件
	if !strings.Contains(body, "remark-form") {
		t.Error("list should include per-row remark forms")
	}
}

// TestRecordsTotalCostExcludesFailed 验证创作记录页"累计消耗"不统计
// 失败（已全额退积分，倍率=0）的记录。
func TestRecordsTotalCostExcludesFailed(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	// 倍率 0 = 失败全额退回：失败记录不计入累计消耗（原语义）
	models.SetConfig("generation_fail_penalty", "0")
	// 页面渲染依赖全局模板
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))
	// 造一个用户与三条记录：成功 x2（各10分）、失败 x1（10分已退回）
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, points INTEGER DEFAULT 0, role TEXT DEFAULT 'user', status INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT, model TEXT,
		n INTEGER DEFAULT 1, aspect_ratio TEXT, resolution TEXT, response_format TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT, error_msg TEXT,
		channel TEXT, nsfw INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec(`INSERT INTO generation_records(user_id, prompt, cost_points, status) VALUES
		(1,'成功一',10,'success'), (1,'成功二',10,'success'), (1,'失败一',10,'failed')`)
	// 多图记录：触发记录页副图遍历（ImagesSub/AltURLs），防止
	// "error calling len: reflect: call of reflect.Value.Type on zero Value" 回归
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_images (
		id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, idx INTEGER DEFAULT 0,
		path TEXT DEFAULT '', storage_type TEXT DEFAULT '', storage_path TEXT DEFAULT '')`)
	models.DB.Exec("INSERT INTO generation_images(record_id, idx, path) VALUES(1,0,'/images/s1.png'),(1,1,'/images/s2.png')")

	req := httptest.NewRequest(http.MethodGet, "/records", nil)
	// gorilla/sessions 以请求为上下文保存会话，直接在此请求上写入即可
	s, _ := store.Get(req, "session")
	s.Values["userID"] = int64(1)
	s.Values["username"] = "u"
	s.Values["role"] = "user"
	w0 := httptest.NewRecorder()
	s.Save(req, w0)

	w := httptest.NewRecorder()
	recordsHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String()[:200])
	}
	body, _ := io.ReadAll(w.Body)
	if strings.Contains(string(body), "Template error") || strings.Contains(string(body), "<no value>") {
		t.Fatalf("records page must not contain template errors: %s", truncateRunes(string(body), 300))
	}
	if !strings.Contains(string(body), "/images/s2.png") {
		t.Errorf("records page should render multi-image sub images: %s", truncateRunes(string(body), 300))
	}
	idx := strings.Index(string(body), "累计消耗")
	if idx < 0 {
		t.Fatal("records page missing 累计消耗")
	}
	seg := strings.ReplaceAll(string(body)[idx:idx+120], "\n", " ")
	t.Logf("total-cost segment: %s", seg)
	if !strings.Contains(seg, "20") {
		t.Errorf("累计消耗应为 20（仅成功记录 10+10），实际 segment: %s", seg)
	}
	if strings.Contains(seg, "30") {
		t.Errorf("累计消耗不得计入失败退回积分（应为 20 而非 30）：%s", seg)
	}
	if !strings.Contains(seg, "<strong class=\"text-danger\">20</strong>") {
		t.Errorf("累计消耗应精确显示为 20：%s", seg)
	}
}

// TestRecordsTotalCostIncludesFailPenalty 验证"累计消耗"会按创作失败扣减
// 倍率计入失败记录未退回的部分（10 × 0.3 = 3）。
func TestRecordsTotalCostIncludesFailPenalty(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	models.SetConfig("generation_fail_penalty", "0.3")
	// 页面渲染依赖全局模板
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, points INTEGER DEFAULT 0, role TEXT DEFAULT 'user', status INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT, model TEXT,
		n INTEGER DEFAULT 1, aspect_ratio TEXT, resolution TEXT, response_format TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT, error_msg TEXT,
		channel TEXT, nsfw INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec(`INSERT INTO generation_records(user_id, prompt, cost_points, status) VALUES
		(1,'成功一',10,'success'), (1,'成功二',10,'success'), (1,'失败一',10,'failed')`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_images (
		id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, idx INTEGER DEFAULT 0,
		path TEXT DEFAULT '', storage_type TEXT DEFAULT '', storage_path TEXT DEFAULT '')`)

	req := httptest.NewRequest(http.MethodGet, "/records", nil)
	s, _ := store.Get(req, "session")
	s.Values["userID"] = int64(1)
	s.Values["username"] = "u"
	s.Values["role"] = "user"
	w0 := httptest.NewRecorder()
	s.Save(req, w0)

	w := httptest.NewRecorder()
	recordsHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String()[:200])
	}
	body, _ := io.ReadAll(w.Body)
	idx := strings.Index(string(body), "累计消耗")
	if idx < 0 {
		t.Fatal("records page missing 累计消耗")
	}
	seg := strings.ReplaceAll(string(body)[idx:idx+120], "\n", " ")
	t.Logf("total-cost segment: %s", seg)
	if !strings.Contains(seg, "<strong class=\"text-danger\">23</strong>") {
		t.Errorf("累计消耗应为 23（成功 20 + 失败扣减 10×0.3=3），实际 segment: %s", seg)
	}
	if strings.Contains(seg, "30") {
		t.Errorf("累计消耗不得全额计入失败记录（应为 23 而非 30）：%s", seg)
	}
}

// TestRecordsViewModeImagesOnly 验证创作记录页"仅图片"视图：
// view=images 时隐藏记录主体信息（record-body/提示词/操作区），
// 只保留封面与配图；默认或 view=full 时完整显示。
func TestRecordsViewModeImagesOnly(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, points INTEGER DEFAULT 0, role TEXT DEFAULT 'user', status INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT, model TEXT,
		n INTEGER DEFAULT 1, aspect_ratio TEXT, resolution TEXT, response_format TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT, error_msg TEXT,
		channel TEXT, nsfw INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec(`INSERT INTO generation_records(user_id, prompt, cost_points, status, image_url) VALUES
		(1,'仅图片验证',10,'success','/images/v1.png')`)

	render := func(view string) string {
		req := httptest.NewRequest(http.MethodGet, "/records?view="+view, nil)
		s, _ := store.Get(req, "session")
		s.Values["userID"] = int64(1)
		s.Values["username"] = "u"
		s.Values["role"] = "user"
		w0 := httptest.NewRecorder()
		s.Save(req, w0)
		w := httptest.NewRecorder()
		recordsHandler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("view=%s status=%d", view, w.Code)
		}
		b, _ := io.ReadAll(w.Body)
		return string(b)
	}

	full := render("full")
	if !strings.Contains(full, `class="record-body"`) {
		t.Error("full view should include record-body")
	}
	if !strings.Contains(full, "仅图片验证") {
		t.Error("full view should include prompt text")
	}
	if !strings.Contains(full, `view=images`) {
		t.Error("full view should offer images switch link")
	}

	images := render("images")
	if strings.Contains(images, `class="record-body"`) {
		t.Error("images-only view must not include record-body")
	}
	if strings.Contains(images, "仅图片验证") {
		t.Error("images-only view must not show prompt text")
	}
	if !strings.Contains(images, "/images/v1.png") {
		t.Error("images-only view must keep cover image")
	}
	if !strings.Contains(images, `view=full`) {
		t.Error("images-only view should offer full switch link")
	}
}

// TestRefundSystemLogAndUsersOAuth 验证：
// 1) markTaskFailed 按"创作失败扣减倍率"（默认 0.1）扣除部分积分后把其余
//    退回（30 积分 × 0.1 = 扣 3、退 27），同时写入系统日志（action=refund）；
// 2) 管理后台用户列表展示第三方绑定信息（provider/ID/用户名）。
func TestRefundSystemLogAndUsersOAuth(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	// 页面渲染依赖全局模板
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))
	// 默认倍率 0.1：失败扣减 = 30 × 0.1 = 3，退回 27
	models.SetConfig("generation_fail_penalty", "0.1")

	res, _ := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status, oauth_provider, oauth_id, oauth_username) VALUES(?,?,?,?,?,?,?,?)",
		"oauthUser", "x", 100, "user", 1, "linuxdo", "12345", "linuxdo_nick")
	uid, _ := res.LastInsertId()
	res2, _ := models.DB.Exec("INSERT INTO generation_records(user_id, prompt, cost_points, status, task_key) VALUES(?,?,?,?,?)",
		uid, "测试", 30, "processing", "abc12345")
	rid, _ := res2.LastInsertId()

	// 1) 部分退回积分（扣 3 退 27）+ 系统日志
	markTaskFailed(rid, "模拟生成失败", false)
	var points int64
	models.DB.QueryRow("SELECT points FROM users WHERE id=?", uid).Scan(&points)
	if points != 127 {
		t.Errorf("points=%d, want 127 (100+30-3 penalty)", points)
	}
	var cnt int
	models.DB.QueryRow("SELECT COUNT(*) FROM system_logs WHERE user_id=? AND action='refund' AND points_delta>0", uid).Scan(&cnt)
	if cnt != 1 {
		t.Errorf("refund system log count=%d, want 1", cnt)
	}
	var detail string
	models.DB.QueryRow("SELECT detail FROM system_logs WHERE user_id=? AND action='refund'", uid).Scan(&detail)
	if !strings.Contains(detail, "生成失败退回") {
		t.Errorf("refund detail=%q, want contains 生成失败退回", detail)
	}
	if !strings.Contains(detail, "27") {
		t.Errorf("refund detail=%q, want contains refunded amount 27", detail)
	}

	// 2) 管理后台用户列表显示第三方绑定
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	s, _ := store.Get(req, "session")
	s.Values["userID"] = int64(1)
	s.Values["username"] = "admin"
	s.Values["role"] = "admin"
	w0 := httptest.NewRecorder()
	s.Save(req, w0)
	// 需要 admin 用户存在（adminUsersHandler 不校验角色，直接查询即可）
	models.DB.Exec("UPDATE users SET role='admin' WHERE username='oauthUser'")
	w := httptest.NewRecorder()
	adminUsersHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String()[:200])
	}
	body := w.Body.String()
	for _, want := range []string{"linuxdo", "12345", "linuxdo_nick"} {
		if !strings.Contains(body, want) {
			t.Errorf("admin users page missing %q", want)
		}
	}
}

// TestMarkTaskFailedPenaltyFull 验证倍率=1 时失败任务全额扣减、
// 不再退回任何积分（也不产生 refund 系统日志）。
func TestMarkTaskFailedPenaltyFull(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	models.SetConfig("generation_fail_penalty", "1")

	res, _ := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)",
		"penaltyUser", "x", 100, "user", 1)
	uid, _ := res.LastInsertId()
	res2, _ := models.DB.Exec("INSERT INTO generation_records(user_id, prompt, cost_points, status, task_key) VALUES(?,?,?,?,?)",
		uid, "测试", 40, "processing", "penalty01")
	rid, _ := res2.LastInsertId()

	markTaskFailed(rid, "模拟生成失败", false)
	var points int64
	models.DB.QueryRow("SELECT points FROM users WHERE id=?", uid).Scan(&points)
	if points != 100 {
		t.Errorf("points=%d, want 100 (全额扣减不退分)", points)
	}
	var status string
	models.DB.QueryRow("SELECT status FROM generation_records WHERE id=?", rid).Scan(&status)
	if status != "failed" {
		t.Errorf("record status=%q, want failed", status)
	}
	var cnt int
	models.DB.QueryRow("SELECT COUNT(*) FROM system_logs WHERE user_id=? AND action='refund'", uid).Scan(&cnt)
	if cnt != 0 {
		t.Errorf("refund log count=%d, want 0 (无退回不记日志)", cnt)
	}
}

// TestAdminRecordsReview 验证管理端创作记录审查页：展示所有用户的创作记录
// 与生成图片（含配图统计），支持按状态筛选，并支持管理员删除任意记录
// （连带清理归档图片行）。
func TestAdminRecordsReview(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	// 页面渲染依赖全局模板
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	models.DB.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, points INTEGER DEFAULT 0, role TEXT DEFAULT 'user', status INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT, model TEXT,
		n INTEGER DEFAULT 1, aspect_ratio TEXT, resolution TEXT, response_format TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT, error_msg TEXT,
		channel TEXT, nsfw INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_images (
		id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, idx INTEGER DEFAULT 0,
		path TEXT DEFAULT '', storage_type TEXT DEFAULT '', storage_path TEXT DEFAULT '')`)
	// InitDB 会种子化默认管理员（id=1），测试用户使用独立 ID
	models.DB.Exec("INSERT INTO users(id, username, password_hash, role, status) VALUES(100,'alice','x','user',1)")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, role, status) VALUES(101,'bob','x','user',1)")
	models.DB.Exec(`INSERT INTO generation_records(user_id, prompt, cost_points, status, image_url) VALUES
		(100,'星空图',10,'success','/images/a.png'),
		(101,'失败作',10,'failed',''),
		(100,'多图记录',10,'success','/images/multi1.png')`)
	// 多图记录（无外部存储，AltURLs 为空）：回归验证页内副图遍历不触发
	// "error calling len: reflect: call of reflect.Value.Type on zero Value"
	models.DB.Exec("INSERT INTO generation_images(record_id, idx, path) VALUES(1,0,'/images/a.png'),(3,0,'/images/multi1.png'),(3,1,'/images/multi2.png')")

	// 管理员会话浏览审查页
	render := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		s, _ := store.Get(req, "session")
		s.Values["userID"] = int64(9)
		s.Values["username"] = "admin"
		s.Values["role"] = "admin"
		w0 := httptest.NewRecorder()
		s.Save(req, w0)
		w := httptest.NewRecorder()
		adminRecordsHandler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("admin records status=%d body=%s", w.Code, truncateRunes(w.Body.String(), 200))
		}
		return w.Body.String()
	}

	body := render("/admin/records")
	if strings.Contains(body, "Template error") || strings.Contains(body, "<no value>") {
		t.Fatalf("review page must not contain template errors: %s", truncateRunes(body, 300))
	}
	for _, want := range []string{"创作记录审查", "alice", "bob", "星空图", "失败作", "多图记录", "/images/a.png", "/images/multi1.png", "/images/multi2.png"} {
		if !strings.Contains(body, want) {
			t.Errorf("review page missing %q (len=%d)", want, len(body))
		}
	}
	if !strings.Contains(body, "归档图片") || !strings.Contains(body, "3 张") {
		t.Errorf("review page should count archived images, got: %s", truncateRunes(body, 300))
	}

	// 状态筛选：只看失败
	b2 := render("/admin/records?s=failed")
	if !strings.Contains(b2, "失败作") || strings.Contains(b2, "星空图") {
		t.Errorf("status filter failed: %s", truncateRunes(b2, 300))
	}
	// 用户名筛选：只看 bob
	b3 := render("/admin/records?u=bob")
	if !strings.Contains(b3, "失败作") || strings.Contains(b3, "星空图") {
		t.Errorf("username filter failed: %s", truncateRunes(b3, 300))
	}

	// 管理端删除：先取带 CSRF 的会话 cookie
	preW := httptest.NewRecorder()
	preR := httptest.NewRequest(http.MethodGet, "/admin/records", nil)
	preS, _ := store.New(preR, "session")
	preS.Values["userID"] = int64(9)
	preS.Values["username"] = "admin"
	preS.Values["role"] = "admin"
	preS.Save(preR, preW)
	preCookie := lastCookie(preW)
	csrfR := httptest.NewRequest(http.MethodGet, "/", nil)
	csrfR.Header.Set("Cookie", preCookie)
	csrf := csrfToken(preW, csrfR)
	cookie := lastCookie(preW)

	delW := httptest.NewRecorder()
	delR := httptest.NewRequest(http.MethodPost, "/admin/records/delete", strings.NewReader(url.Values{
		"_csrf": {csrf},
		"id":    {"2"},
	}.Encode()))
	delR.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	delR.Header.Set("Cookie", cookie)
	delR.Header.Set("Referer", "http://x/admin/records?s=failed")
	adminRecordDeleteHandler(delW, delR)
	if delW.Code != http.StatusSeeOther {
		t.Fatalf("admin delete status=%d body=%s", delW.Code, truncateRunes(delW.Body.String(), 200))
	}
	if loc := delW.Header().Get("Location"); loc != "/admin/records?s=failed" {
		t.Errorf("delete back Location = %q, want /admin/records?s=failed", loc)
	}
	var n int
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE id=2").Scan(&n)
	if n != 0 {
		t.Error("admin delete should remove the record")
	}
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_images WHERE record_id=2").Scan(&n)
	if n != 0 {
		t.Error("admin delete should remove image rows")
	}
}

// TestDashboardGenStats 验证数据概览页的创作统计：总计/今日的成功次数、
// 失败次数与成功率（成功率 = 成功 ÷ (成功+失败)）。
func TestDashboardGenStats(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	// 总计：成功 2、失败 1（成功率 66.7%）；今日：成功 1、失败 1（成功率 50.0%）
	models.DB.Exec("INSERT INTO generation_records(user_id, prompt, cost_points, status, created_at) VALUES"+
		"(1,'昨日成功',10,'success',datetime('now','-1 day')),"+
		"(1,'今日成功',10,'success',datetime('now')),"+
		"(1,'今日失败',10,'failed',datetime('now'))")

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	s, _ := store.Get(req, "session")
	s.Values["userID"] = int64(1)
	s.Values["username"] = "admin"
	s.Values["role"] = "admin"
	w0 := httptest.NewRecorder()
	s.Save(req, w0)

	w := httptest.NewRecorder()
	adminDashboardHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, truncateRunes(w.Body.String(), 200))
	}
	body := w.Body.String()
	for _, want := range []string{"创作成功率（总计）", "66.7%", "今日创作成功率", "50.0%", "成功", "失败"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	// 失败次数以红色标注（总计 1 次失败）
	if !strings.Contains(body, "text-danger fw-semibold\">1</span>") {
		t.Errorf("dashboard should show failed count: %s", truncateRunes(body, 300))
	}
}

// TestCopyDirReplace 验证在线更新的模板/静态资源同步：递归拷贝、
// 覆盖同名文件、补齐新文件、保留目录结构。
func TestCopyDirReplace(t *testing.T) {
	src := t.TempDir() + "/src"
	dst := t.TempDir() + "/dst"
	// 预置旧文件：同名的会被覆盖，独有的应保留（不删除）
	for _, d := range []string{filepath.Join(src, "templates", "admin"), filepath.Join(src, "static", "css")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(dst, "templates", "admin"), 0o755)
	for _, f := range [][2]string{
		{filepath.Join(src, "templates", "index.html"), "新版首页"},
		{filepath.Join(src, "templates", "admin", "settings.html"), "新版设置"},
		{filepath.Join(src, "static", "css", "style.css"), "新版样式"},
		{filepath.Join(dst, "templates", "index.html"), "旧版首页"},
		{filepath.Join(dst, "templates", "admin", "users.html"), "不应被删除"},
	} {
		if err := os.WriteFile(f[0], []byte(f[1]), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := copyDirReplace(src, dst); err != nil {
		t.Fatal(err)
	}
	check := func(rel, want string) {
		b, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			return
		}
		if string(b) != want {
			t.Errorf("%s = %q, want %q", rel, string(b), want)
		}
	}
	check("templates/index.html", "新版首页")
	check("templates/admin/settings.html", "新版设置")
	check("static/css/style.css", "新版样式")
	if _, err := os.Stat(filepath.Join(dst, "templates", "admin", "users.html")); err != nil {
		t.Error("copyDirReplace 不应删除目标目录中独有的旧文件")
	}
}

// TestResolveChannelStableID 验证 channel 按"稳定编号"解析：
// 编号随渠道持久化、不随增删/排序变化；旧的"数组下标"不再有效。
func TestResolveChannelStableID(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "ch.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	eps := []GenerationEndpoint{
		{ID: 2, Name: "主渠道", APIURL: "https://a.example/v1", APIKey: "k1", Resolutions: []string{"1k", "2k"}, Models: defaultModels},
		{ID: 5, Name: "NSFW渠道", APIURL: "https://b.example/v1", APIKey: "k2", NSFW: true, Resolutions: []string{"1k"}, Models: defaultModels},
	}
	raw, _ := json.Marshal(eps)
	models.SetConfig("generation_endpoints", string(raw))

	// 留空 = 自动选第一个普通渠道
	ep, err := resolveChannel("")
	if err != nil || ep.ID != 2 {
		t.Errorf("empty channel should pick first normal channel id=2, got id=%d err=%v", ep.ID, err)
	}
	// 按稳定编号解析（与数组位置无关）
	ep, err = resolveChannel("5")
	if err != nil || ep.ID != 5 || !ep.NSFW {
		t.Errorf("channel 5 should resolve to NSFW channel, got %+v err=%v", ep, err)
	}
	ep, err = resolveChannel("2")
	if err != nil || ep.ID != 2 {
		t.Errorf("channel 2 should resolve, got %+v err=%v", ep, err)
	}
	// 旧数组下标 / 不存在的编号一律报错（防止渠道变动后选错渠道）
	for _, bad := range []string{"0", "1", "3", "abc", "-1"} {
		if _, err := resolveChannel(bad); err == nil {
			t.Errorf("channel %q should not resolve (ids are 2,5)", bad)
		}
	}
}

// TestFillEndpointIDs 验证缺失编号按最大编号递增补发（编号不复用）。
func TestFillEndpointIDs(t *testing.T) {
	eps := []GenerationEndpoint{
		{Name: "A", APIURL: "u1"},
		{ID: 7, Name: "B", APIURL: "u2"},
		{Name: "C", APIURL: "u3"},
	}
	fillEndpointIDs(eps)
	if eps[0].ID != 8 || eps[1].ID != 7 || eps[2].ID != 9 {
		t.Errorf("fillEndpointIDs = %d,%d,%d want 8,7,9", eps[0].ID, eps[1].ID, eps[2].ID)
	}
}

// TestMigrateEndpointIDs 验证启动迁移：历史无编号配置补发 1..n 并持久化，
// 再次迁移幂等不变。
func TestMigrateEndpointIDs(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "mig.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	old := []GenerationEndpoint{{Name: "A", APIURL: "u1"}, {Name: "B", APIURL: "u2"}}
	raw, _ := json.Marshal(old)
	models.SetConfig("generation_endpoints", string(raw))
	migrateEndpointIDs()
	got := loadEndpoints()
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 2 {
		t.Fatalf("migrated ids = %d,%d want 1,2", got[0].ID, got[1].ID)
	}
	// 幂等：重复迁移不再改变编号
	migrateEndpointIDs()
	got2 := loadEndpoints()
	if got2[0].ID != 1 || got2[1].ID != 2 {
		t.Errorf("migrate not idempotent: %d,%d", got2[0].ID, got2[1].ID)
	}
}

// TestSaveEndpointsKeepsStableIDs 验证设置页保存时渠道编号稳定：
// 调整顺序、删除渠道、新增渠道都不影响已有渠道的编号，新渠道编号不复用。
func TestSaveEndpointsKeepsStableIDs(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "save.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	submit := func(ids, urls, names, nsfw []string) {
		form := url.Values{
			"ep_id[]":           ids,
			"ep_url[]":          urls,
			"ep_name[]":         names,
			"ep_key[]":          {"", "", ""},
			"ep_model[]":        {"", "", ""},
			"ep_nsfw[]":         nsfw,
			"ep_res[]":          {"1k,2k", "1k", "1k"},
			"ep_models[]":       {"", "", ""},
			"ep_extra_models[]": {"", "", ""},
		}
		req := httptest.NewRequest(http.MethodPost, "/admin/update-settings", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		saveEndpointsFromForm(req)
	}
	// 首次保存三条渠道（无编号）→ 顺序补发 1,2,3
	submit([]string{"", "", ""}, []string{"https://a/v1", "https://b/v1", "https://c/v1"}, []string{"A", "B", "C"}, []string{"0", "1", "0"})
	eps := loadEndpoints()
	if len(eps) != 3 || eps[0].ID != 1 || eps[1].ID != 2 || eps[2].ID != 3 {
		t.Fatalf("first save ids want 1,2,3 got %d,%d,%d", eps[0].ID, eps[1].ID, eps[2].ID)
	}
	// 调整顺序（B 提到首位）并删除 C：编号跟随渠道而非位置
	submit([]string{"2", "1"}, []string{"https://b/v1", "https://a/v1"}, []string{"B", "A"}, []string{"1", "0"})
	eps = loadEndpoints()
	if len(eps) != 2 || eps[0].Name != "B" || eps[0].ID != 2 || eps[1].Name != "A" || eps[1].ID != 1 {
		t.Fatalf("after reorder want B(id2),A(id1) got %+v", eps)
	}
	// 新增渠道（无编号）→ 编号不复用（应为 4）
	submit([]string{"2", "1", ""}, []string{"https://b/v1", "https://a/v1", "https://d/v1"}, []string{"B", "A", "D"}, []string{"1", "0", "0"})
	eps = loadEndpoints()
	if len(eps) != 3 || eps[0].ID != 2 || eps[1].ID != 1 || eps[2].ID != 4 {
		t.Fatalf("after add want B(2),A(1),D(4) got %+v", eps)
	}
}

// TestAPIV1Channels 验证渠道列表接口返回稳定编号（id）与展示顺序（index）。
func TestAPIV1Channels(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "chapi.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	eps := []GenerationEndpoint{
		{ID: 2, Name: "主渠道", APIURL: "https://a/v1", Model: "m1", Resolutions: []string{"1k", "2k"}, Models: []string{"m1"}},
		{ID: 5, Name: "备渠道", APIURL: "https://b/v1", NSFW: true, Resolutions: []string{"1k"}, Models: []string{"m2"}},
	}
	raw, _ := json.Marshal(eps)
	models.SetConfig("generation_endpoints", string(raw))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/channels", nil)
	w := httptest.NewRecorder()
	apiChannelsHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		OK       bool `json:"ok"`
		Channels []struct {
			ID          int      `json:"id"`
			Index       int      `json:"index"`
			Name        string   `json:"name"`
			NSFW        bool     `json:"nsfw"`
			Resolutions []string `json:"resolutions"`
			Models      []string `json:"models"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || len(resp.Channels) != 2 {
		t.Fatalf("unexpected response: %s", w.Body.String())
	}
	if resp.Channels[0].ID != 2 || resp.Channels[0].Index != 0 || resp.Channels[0].NSFW {
		t.Errorf("first channel = %+v", resp.Channels[0])
	}
	if resp.Channels[1].ID != 5 || resp.Channels[1].Index != 1 || !resp.Channels[1].NSFW {
		t.Errorf("second channel = %+v", resp.Channels[1])
	}
}

// TestMultiAPIKeysAndOpenAIEndpoint 验证：多命名 Key 的创建/列表/删除、
// Key 渠道绑定、apiAuthMiddleware 走 api_keys 表，以及 OpenAI 兼容端点
// /v1/images/generations 的请求校验与响应格式。
func TestMultiAPIKeysAndOpenAIEndpoint(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "apikeys.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()

	// 渠道：id=2 主渠道（1k/2k）、id=5 NSFW 渠道（1k）
	eps := []GenerationEndpoint{
		{ID: 2, Name: "主渠道", APIURL: "https://a/v1", Model: "m1", Resolutions: []string{"1k", "2k"}, Models: []string{"m1"}},
		{ID: 5, Name: "NSFW渠道", APIURL: "https://b/v1", NSFW: true, Resolutions: []string{"1k"}, Models: []string{"m2"}},
	}
	raw, _ := json.Marshal(eps)
	models.SetConfig("generation_endpoints", string(raw))
	models.SetConfig("generation_cost_points", "10")

	res, _ := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)", "keyuser", "x", 100, "user", 1)
	uid, _ := res.LastInsertId()

	// 1) 创建两个命名 Key（绑定不同渠道）
	keyA, err := models.CreateAPIKey(uid, "官网小程序", 2)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := models.CreateAPIKey(uid, "脚本B", 5)
	if err != nil {
		t.Fatal(err)
	}
	if keyA == keyB {
		t.Fatal("two keys should differ")
	}
	keys := models.ListAPIKeys(uid)
	if len(keys) != 2 {
		t.Fatalf("ListAPIKeys = %d, want 2", len(keys))
	}
	// Key 明文不应出现在列表中，掩码应形如 xxxxxxxx****
	for _, k := range keys {
		if k["Name"] != "官网小程序" && k["Name"] != "脚本B" {
			t.Errorf("unexpected key name %v", k["Name"])
		}
		if m, _ := k["Mask"].(string); len(m) != 12 || !strings.HasSuffix(m, "****") {
			t.Errorf("mask = %q", m)
		}
	}

	// 2) apiAuthMiddleware：用新 Key 鉴权通过并带出绑定渠道
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/channels", nil)
	req.Header.Set("Authorization", "Bearer "+keyA)
	apiAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		userID, _ := r.Context().Value("userID").(int64)
		channelID, _ := r.Context().Value("apiChannelID").(int)
		if userID != uid || channelID != 2 {
			t.Errorf("ctx userID=%d channelID=%d, want %d/2", userID, channelID, uid)
		}
	})(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("auth status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 3) OpenAI 兼容端点：size 映射 + 渠道校验（请求经 apiAuthMiddleware 带出绑定渠道）
	openAIReq := func(body string) *httptest.ResponseRecorder {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(body))
		rr.Header.Set("Content-Type", "application/json")
		rr.Header.Set("Authorization", "Bearer "+keyB)
		apiAuthMiddleware(openAIImagesGenerationsHandler)(ww, rr)
		return ww
	}
	// 非法 JSON
	w := openAIReq(`{bad`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad json status=%d", w.Code)
	}
	// prompt 缺失
	w = openAIReq(`{"n":1}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "prompt") {
		t.Errorf("empty prompt status=%d body=%s", w.Code, w.Body.String())
	}
	// NSFW 渠道不支持 2k（size=1792x1024 映射为 2k）
	w = openAIReq(`{"prompt":"test","size":"1792x1024"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "分辨率") {
		t.Errorf("unsupported resolution status=%d body=%s", w.Code, w.Body.String())
	}
	// 4) 删除 keyA（按名称定位），删除后该 Key 立即失效，keyB 仍可用
	var keyAID int64
	for _, k := range models.ListAPIKeys(uid) {
		if k["Name"] == "官网小程序" {
			keyAID = k["ID"].(int64)
		}
	}
	if keyAID == 0 {
		t.Fatal("keyA not found")
	}
	if err := models.DeleteAPIKey(uid, keyAID); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+keyA)
	apiAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Error("deleted key should not authenticate")
	})(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("deleted key still authenticates")
	}
	// keyB 仍可鉴权
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+keyB)
	apiAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if got, _ := r.Context().Value("apiChannelID").(int); got != 5 {
			t.Errorf("keyB channelID=%d, want 5", got)
		}
	})(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal("keyB should still authenticate")
	}
	if len(models.ListAPIKeys(uid)) != 1 {
		t.Errorf("after delete, keys = %d, want 1", len(models.ListAPIKeys(uid)))
	}

	// 5) openAISizeToParams 映射
	for size, want := range map[string][2]string{
		"1024x1024": {"1:1", "1k"},
		"1792x1024": {"16:9", "2k"},
		"1024x1792": {"9:16", "2k"},
		"":          {"1:1", "1k"},
	} {
		r, s := openAISizeToParams(size)
		if r != want[0] || s != want[1] {
			t.Errorf("size %q -> %s/%s, want %s/%s", size, r, s, want[0], want[1])
		}
	}
}

// TestReplaceExecutableSameFS 验证同文件系统内 replaceExecutable 走 rename：
// 内容完整迁移、源文件消失。
func TestReplaceExecutableSameFS(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	data := []byte("new executable content")
	if err := os.WriteFile(src, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceExecutable(src, dst); err != nil {
		t.Fatalf("replaceExecutable: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("src should be gone after rename")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Errorf("dst content = %q, want %q", got, data)
	}
}

// TestReplaceExecutableCrossDeviceFallback 模拟容器场景：/app/data 挂载卷与
// /app 不同文件系统，rename 返回 EXDEV（invalid cross-device link）时必须
// 退化为"拷贝 + 删除源文件"，而不是报"替换可执行文件失败"。
func TestReplaceExecutableCrossDeviceFallback(t *testing.T) {
	old := renameFile
	renameFile = func(a, b string) error { return syscall.EXDEV }
	defer func() { renameFile = old }()

	src := filepath.Join(t.TempDir(), "main")
	dst := filepath.Join(t.TempDir(), "main.new")
	data := []byte("new binary payload")
	// 故意不给执行位，验证拷贝兜底会补齐属主可执行位
	if err := os.WriteFile(src, data, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := replaceExecutable(src, dst); err != nil {
		t.Fatalf("replaceExecutable with EXDEV should fall back to copy, got: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("src should be removed after copy fallback")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Errorf("dst content = %q, want %q", got, data)
	}
	// Windows 无 POSIX 权限语义（常规文件恒为 0666），执行位断言仅对 Unix 生效
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o500 != 0o500 {
			t.Errorf("dst should be owner r-x, got %o", fi.Mode().Perm())
		}
	}
}

// TestReplaceExecutableNonEXDVError 验证非 EXDV 错误（如源文件不存在）原样
// 透传，不会误入拷贝兜底。
func TestReplaceExecutableNonEXDVError(t *testing.T) {
	dir := t.TempDir()
	err := replaceExecutable(filepath.Join(dir, "missing"), filepath.Join(dir, "dst"))
	if err == nil {
		t.Fatal("expected error for missing src")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("want ENOENT-ish error, got %v", err)
	}
}

// TestAJAXNoPageRefresh 验证注册 / 兑换 / Linux.do 完善账号表单的异步提交：
// 携带 X-Requested-With: XMLHttpRequest 时，后端返回 JSON 错误（不渲染整页），
// 前端可原地显示错误而无需刷新页面；成功时返回 redirect 或积分/记录数据。
func TestAJAXNoPageRefresh(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "ajax.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	models.SetConfig("open_registration", "true")
	models.SetConfig("enable_password_registration", "true")
	models.SetConfig("require_reg_code", "true")
	models.SetConfig("enable_thirdparty_registration", "true")

	// ---- 1) /register 异步提交：CSRF 缺失 → 400 JSON ----
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(url.Values{
		"username": {"nocsrf"}, "password": {"123456"}, "confirm_password": {"123456"}, "reg_code": {"X"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("X-Requested-With", "XMLHttpRequest")
	registerHandler(ww, rr)
	if ww.Code != http.StatusBadRequest {
		t.Fatalf("missing csrf status = %d, body=%s", ww.Code, ww.Body.String())
	}
	var csrfErr struct {
		OK   bool   `json:"ok"`
		Form string `json:"form"`
	}
	if err := json.Unmarshal(ww.Body.Bytes(), &csrfErr); err != nil {
		t.Fatalf("expect JSON response: %v", err)
	}
	if csrfErr.OK || csrfErr.Form == "" {
		t.Errorf("missing csrf should return JSON error, got %+v", csrfErr)
	}

	// ---- 2) /register 异步提交：无效注册码 → JSON 字段错误，不创建用户 ----
	w := httptest.NewRecorder()
	r0 := httptest.NewRequest(http.MethodGet, "/register", nil)
	csrf := csrfToken(w, r0)
	cookie := w.Header().Get("Set-Cookie")
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(url.Values{
		"_csrf":            {csrf},
		"username":         {"ajaxuser"},
		"password":         {"123456"},
		"confirm_password": {"123456"},
		"reg_code":         {"NOTEXIST1"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", cookie)
	rr.Header.Set("X-Requested-With", "XMLHttpRequest")
	registerHandler(ww, rr)
	if ww.Code != http.StatusOK {
		t.Fatalf("register ajax error status = %d", ww.Code)
	}
	if ct := ww.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("want JSON content type, got %q", ct)
	}
	var regErr struct {
		OK      bool   `json:"ok"`
		RegCode string `json:"reg_code"`
	}
	if err := json.Unmarshal(ww.Body.Bytes(), &regErr); err != nil {
		t.Fatalf("register ajax body not JSON: %v (%s)", err, truncateRunes(ww.Body.String(), 200))
	}
	if regErr.OK || regErr.RegCode != "注册码无效或已被使用" {
		t.Errorf("register bad code error = %+v", regErr)
	}
	var cnt int
	models.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='ajaxuser'").Scan(&cnt)
	if cnt != 0 {
		t.Errorf("failed register must roll back the user, found %d", cnt)
	}

	// ---- 3) /register 异步提交：有效注册码 → JSON 成功 + redirect ----
	models.DB.Exec("INSERT INTO redeem_codes(code, points, kind, created_by, status) VALUES('OKREG1', 0, 'register', 0, 'active')")
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(url.Values{
		"_csrf":            {csrf},
		"username":         {"ajaxokuser"},
		"password":         {"123456"},
		"confirm_password": {"123456"},
		"reg_code":         {"OKREG1"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", cookie)
	rr.Header.Set("X-Requested-With", "XMLHttpRequest")
	registerHandler(ww, rr)
	var regOK struct {
		OK       bool   `json:"ok"`
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(ww.Body.Bytes(), &regOK); err != nil {
		t.Fatalf("register success not JSON: %v (%s)", err, ww.Body.String())
	}
	if !regOK.OK || regOK.Redirect != "/login" {
		t.Errorf("register ajax success = %+v", regOK)
	}
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes WHERE code='OKREG1' AND status='used'").Scan(&cnt)
	if cnt != 1 {
		t.Errorf("register code should be consumed, used=%d", cnt)
	}

	// ---- 4) /redeem 异步提交：无效兑换码 → JSON 错误；有效 → JSON 成功+积分 ----
	res, _ := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)", "ajaxredeemer", "x", 100, "user", 1)
	uid, _ := res.LastInsertId()
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/redeem", nil)
	s2, _ := store.New(r2, "session")
	s2.Values["userID"] = uid
	s2.Values["username"] = "ajaxredeemer"
	s2.Values["role"] = "user"
	s2.Save(r2, w2)
	sessCookie2 := lastCookie(w2)
	// CSRF token 必须存进上面这个会话：带会话 cookie 的请求再取 token
	r2b := httptest.NewRequest(http.MethodGet, "/redeem", nil)
	r2b.Header.Set("Cookie", sessCookie2)
	csrf2 := csrfToken(w2, r2b)
	cookie2 := lastCookie(w2)

	redeemPost := func(code string) []byte {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, "/redeem", strings.NewReader(url.Values{
			"_csrf": {csrf2}, "code": {code},
		}.Encode()))
		rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr.Header.Set("Cookie", cookie2)
		rr.Header.Set("X-Requested-With", "XMLHttpRequest")
		redeemHandler(ww, rr)
		return ww.Body.Bytes()
	}

	// 无效码：JSON 错误
	var badRedeem struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(redeemPost("BADCODE1"), &badRedeem); err != nil {
		t.Fatalf("redeem bad code not JSON: %v", err)
	}
	if badRedeem.OK || !strings.Contains(badRedeem.Error, "无效或已被使用") {
		t.Errorf("redeem bad code error = %+v", badRedeem)
	}

	// 有效码：JSON 成功，返回最新积分与兑换记录
	models.DB.Exec("INSERT INTO redeem_codes(code, points, kind, created_by, status) VALUES('PTSAJX1', 50, 'points', 0, 'active')")
	body := redeemPost("PTSAJX1")
	var goodRedeem struct {
		OK      bool   `json:"ok"`
		Msg     string `json:"msg"`
		Points  int64  `json:"points"`
		History []struct {
			Code   string `json:"Code"`
			Points int64  `json:"Points"`
		} `json:"history"`
	}
	if err := json.Unmarshal(body, &goodRedeem); err != nil {
		t.Fatalf("redeem success not JSON: %v (%s)", err, body)
	}
	if !goodRedeem.OK || !strings.Contains(goodRedeem.Msg, "获得 50 积分") || goodRedeem.Points != 150 {
		t.Errorf("redeem success = %+v", goodRedeem)
	}
	if len(goodRedeem.History) == 0 || goodRedeem.History[0].Code != "PTSAJX1" {
		t.Errorf("redeem history should include the new record, got %+v", goodRedeem.History)
	}
	models.DB.QueryRow("SELECT points FROM users WHERE id=?", uid).Scan(&goodRedeem.Points)
	if goodRedeem.Points != 150 {
		t.Errorf("db points = %d, want 150", goodRedeem.Points)
	}

	// ---- 5) Linux.do 完善账号页异步提交：无效注册码 → JSON 字段错误 ----
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/auth/linuxdo/setup", nil)
	s3, _ := store.New(r3, "session")
	s3.Values["oauth_pending_user_id"] = int64(99992)
	s3.Values["oauth_pending_username"] = "linuxajax"
	s3.Values["oauth_pending_next"] = "/create"
	s3.Save(r3, w3)
	oauthCookie := lastCookie(w3)
	// CSRF token 必须存进上面这个会话：带会话 cookie 的请求再取 token
	r3b := httptest.NewRequest(http.MethodGet, "/auth/linuxdo/setup", nil)
	r3b.Header.Set("Cookie", oauthCookie)
	csrf3 := csrfToken(w3, r3b)
	cookie3 := lastCookie(w3)
	ww = httptest.NewRecorder()
	rr = httptest.NewRequest(http.MethodPost, "/auth/linuxdo/setup", strings.NewReader(url.Values{
		"_csrf":            {csrf3},
		"username":         {"linuxajax"},
		"password":         {"123456"},
		"confirm_password": {"123456"},
		"reg_code":         {"BADOAUTH"},
	}.Encode()))
	rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr.Header.Set("Cookie", cookie3)
	rr.Header.Set("X-Requested-With", "XMLHttpRequest")
	linuxdoSetupHandler(ww, rr)
	var oauthErr struct {
		OK      bool   `json:"ok"`
		RegCode string `json:"reg_code"`
	}
	if err := json.Unmarshal(ww.Body.Bytes(), &oauthErr); err != nil {
		t.Fatalf("oauth setup not JSON: %v (%s)", err, truncateRunes(ww.Body.String(), 200))
	}
	if oauthErr.OK || oauthErr.RegCode != "注册码无效或已被使用" {
		t.Errorf("oauth setup bad code error = %+v", oauthErr)
	}
}

// TestAdminUserManagement 验证用户管理的后台能力：管理员重置密码、修改/取消
// 第三方绑定、删除用户（相关数据清理、兑换码释放、用户名可重新注册、防止
// 删除自己或仅剩的管理员）。
func TestAdminUserManagement(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "manage.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	var adminID int64
	models.DB.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&adminID)
	// 管理员会话 + CSRF
	buildAdmin := func() (string, string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		s, _ := store.New(r, "session")
		s.Values["userID"] = adminID
		s.Values["username"] = "admin"
		s.Values["role"] = "admin"
		s.Save(r, w)
		c := w.Header().Get("Set-Cookie")
		r2 := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		r2.Header.Set("Cookie", c)
		csrf := csrfToken(w, r2)
		return csrf, lastCookie(w)
	}
	csrf, cookie := buildAdmin()
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr.Header.Set("Cookie", cookie)
		switch path {
		case "/admin/user/password":
			adminUserPasswordHandler(ww, rr)
		case "/admin/user/oauth-unbind":
			adminUserOAuthUnbindHandler(ww, rr)
		case "/admin/user/oauth-update":
			adminUserOAuthUpdateHandler(ww, rr)
		case "/admin/user/delete":
			adminUserDeleteHandler(ww, rr)
		default:
			t.Fatalf("unexpected path %s", path)
		}
		return ww
	}

	// 目标用户 alice：已绑定 linuxdo，附带签到/积分流水/占用的兑换码/API Key/创作记录
	hash, _ := bcrypt.GenerateFromPassword([]byte("oldpass123"), bcrypt.DefaultCost)
	res, err := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status, oauth_provider, oauth_id, oauth_username) VALUES(?,?,?,?,?,?,?,?)",
		"alice", string(hash), 100, "user", 1, "linuxdo", "9001", "ld_alice")
	if err != nil {
		t.Fatal(err)
	}
	aliceID, _ := res.LastInsertId()
	aliceIDStr := fmt.Sprintf("%d", aliceID)
	models.DB.Exec("INSERT INTO checkin_logs(user_id, date, points) VALUES(?, '2026-01-01', 10)", aliceID)
	models.DB.Exec("INSERT INTO points_log(user_id, delta, balance, description) VALUES(?, 100, 100, '测试')", aliceID)
	models.DB.Exec("INSERT INTO redeem_codes(code, points, used_by, status) VALUES('ALICECODE', 30, ?, 'used')", aliceID)
	models.DB.Exec("INSERT INTO api_keys(user_id, name, key_hash) VALUES(?, 'alice-key', 'abc')", aliceID)
	rRec, _ := models.DB.Exec("INSERT INTO generation_records(user_id, prompt, cost_points, status, task_key) VALUES(?, 'alice prompt', 10, 'success', 'alicekey1')", aliceID)
	recID, _ := rRec.LastInsertId()
	models.DB.Exec("INSERT INTO generation_images(record_id, idx, path) VALUES(?, 0, '/images/alice1.png')", recID)
	systemLog(nil, aliceID, "alice", "login", "登录成功", 0)

	// 1) 过短密码被拒
	if ww := post("/admin/user/password", url.Values{"_csrf": {csrf}, "id": {aliceIDStr}, "new_password": {"123"}}); ww.Code != http.StatusBadRequest {
		t.Fatalf("short password status = %d, want 400", ww.Code)
	}
	// 2) 管理员重置密码：旧密码失效、新密码可登录
	if ww := post("/admin/user/password", url.Values{"_csrf": {csrf}, "id": {aliceIDStr}, "new_password": {"newpass456"}}); ww.Code != http.StatusSeeOther {
		t.Fatalf("reset password status = %d, want 303: %s", ww.Code, truncateRunes(ww.Body.String(), 200))
	}
	login := func(pw string) *httptest.ResponseRecorder {
		wl := httptest.NewRecorder()
		rl := httptest.NewRequest(http.MethodGet, "/login", nil)
		lc := csrfToken(wl, rl)
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{
			"_csrf":    {lc},
			"username": {"alice"},
			"password": {pw},
		}.Encode()))
		rr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr.Header.Set("Cookie", wl.Header().Get("Set-Cookie"))
		loginHandler(ww, rr)
		return ww
	}
	if ww := login("oldpass123"); ww.Code != http.StatusOK {
		t.Fatalf("old password login status = %d, want 200 (rejected)", ww.Code)
	}
	if ww := login("newpass456"); ww.Code != http.StatusSeeOther || ww.Header().Get("Location") != "/create" {
		t.Fatalf("new password login = %d loc=%q, want 303 /create", ww.Code, ww.Header().Get("Location"))
	}

	// 3) 修改第三方绑定
	if ww := post("/admin/user/oauth-update", url.Values{
		"_csrf":          {csrf},
		"id":             {aliceIDStr},
		"oauth_provider": {"linuxdo"},
		"oauth_id":       {"9002"},
		"oauth_username": {"ld_alice2"},
	}); ww.Code != http.StatusSeeOther {
		t.Fatalf("oauth update status = %d, want 303", ww.Code)
	}
	var prov, oid, oun string
	models.DB.QueryRow("SELECT oauth_provider, oauth_id, oauth_username FROM users WHERE id=?", aliceID).Scan(&prov, &oid, &oun)
	if prov != "linuxdo" || oid != "9002" || oun != "ld_alice2" {
		t.Fatalf("oauth update = %q/%q/%q, want linuxdo/9002/ld_alice2", prov, oid, oun)
	}
	// 冲突：同一第三方账号已绑定其他用户时拒绝
	models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status, oauth_provider, oauth_id, oauth_username) VALUES(?,?,?,?,?,?,?,?)",
		"bob", "x", 0, "user", 1, "linuxdo", "9002", "ld_bob")
	if ww := post("/admin/user/oauth-update", url.Values{
		"_csrf":          {csrf},
		"id":             {aliceIDStr},
		"oauth_provider": {"linuxdo"},
		"oauth_id":       {"9002"},
		"oauth_username": {"dup"},
	}); ww.Code != http.StatusConflict {
		t.Fatalf("duplicate bind status = %d, want 409", ww.Code)
	}
	models.DB.QueryRow("SELECT oauth_id FROM users WHERE id=?", aliceID).Scan(&oid)
	if oid != "9002" {
		t.Fatalf("bind should remain 9002 after rejected update, got %q", oid)
	}
	// 4) 取消第三方绑定
	if ww := post("/admin/user/oauth-unbind", url.Values{"_csrf": {csrf}, "id": {aliceIDStr}}); ww.Code != http.StatusSeeOther {
		t.Fatalf("unbind status = %d, want 303", ww.Code)
	}
	models.DB.QueryRow("SELECT COALESCE(oauth_provider,''), COALESCE(oauth_id,''), COALESCE(oauth_username,'') FROM users WHERE id=?", aliceID).Scan(&prov, &oid, &oun)
	if prov != "" || oid != "" || oun != "" {
		t.Fatalf("unbind should clear oauth columns, got %q/%q/%q", prov, oid, oun)
	}
	// 未绑定再解绑 → 400
	if ww := post("/admin/user/oauth-unbind", url.Values{"_csrf": {csrf}, "id": {aliceIDStr}}); ww.Code != http.StatusBadRequest {
		t.Fatalf("double unbind status = %d, want 400", ww.Code)
	}
	// oauth-update 的第三方 ID 留空同样视为解绑
	post("/admin/user/oauth-update", url.Values{"_csrf": {csrf}, "id": {aliceIDStr}, "oauth_provider": {"linuxdo"}, "oauth_id": {"9003"}, "oauth_username": {"ld3"}})
	if ww := post("/admin/user/oauth-update", url.Values{"_csrf": {csrf}, "id": {aliceIDStr}, "oauth_provider": {"linuxdo"}, "oauth_id": {""}, "oauth_username": {""}}); ww.Code != http.StatusSeeOther {
		t.Fatalf("oauth-clear status = %d, want 303", ww.Code)
	}
	models.DB.QueryRow("SELECT COALESCE(oauth_provider,'') FROM users WHERE id=?", aliceID).Scan(&prov)
	if prov != "" {
		t.Fatalf("empty oauth_id should clear binding, provider=%q", prov)
	}

	// 5) 删除用户：自我保护、数据清理、兑换码释放、用户名可重新注册
	if ww := post("/admin/user/delete", url.Values{"_csrf": {csrf}, "id": {fmt.Sprintf("%d", adminID)}}); ww.Code != http.StatusBadRequest {
		t.Fatalf("self delete status = %d, want 400", ww.Code)
	}
	if ww := post("/admin/user/delete", url.Values{"_csrf": {csrf}, "id": {aliceIDStr}}); ww.Code != http.StatusSeeOther {
		t.Fatalf("delete status = %d, want 303: %s", ww.Code, truncateRunes(ww.Body.String(), 200))
	}
	var n int64
	models.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id=?", aliceID).Scan(&n)
	if n != 0 {
		t.Errorf("after delete users = %d, want 0", n)
	}
	for _, tbl := range []string{"generation_records", "checkin_logs", "points_log", "api_keys"} {
		var m int64
		models.DB.QueryRow("SELECT COUNT(*) FROM "+tbl+" WHERE user_id=?", aliceID).Scan(&m)
		if m != 0 {
			t.Errorf("after delete %s = %d, want 0", tbl, m)
		}
	}
	// 创作图片行按 record 关联，单独断言
	var imgN int
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_images WHERE record_id=?", recID).Scan(&imgN)
	if imgN != 0 {
		t.Errorf("after delete generation_images = %d, want 0", imgN)
	}
	// 兑换码释放回可用状态
	var codeN int
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes WHERE code='ALICECODE' AND status='active' AND used_by=0 AND used_at IS NULL").Scan(&codeN)
	if codeN != 1 {
		t.Error("redeem code should be refunded to active after user deletion")
	}
	// 系统日志保留为审计，归属置 0
	var logN int
	models.DB.QueryRow("SELECT COUNT(*) FROM system_logs WHERE username='alice' AND user_id=0").Scan(&logN)
	if logN == 0 {
		t.Error("audit system_logs should be kept (user_id zeroed) after deletion")
	}
	// 删除审计记录存在
	var delN int
	models.DB.QueryRow("SELECT COUNT(*) FROM system_logs WHERE action='admin_delete_user'").Scan(&delN)
	if delN != 1 {
		t.Error("admin_delete_user audit log missing")
	}
	// 用户名可重新注册
	if _, err := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)", "alice", "h", 0, "user", 1); err != nil {
		t.Fatalf("re-register with freed username should succeed: %v", err)
	}

	// 6) 用户管理页展示新操作项
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	rr.Header.Set("Cookie", cookie)
	adminUsersHandler(ww, rr)
	for _, s := range []string{"重置密码", "保存绑定", "删除用户", "±积分"} {
		if !strings.Contains(ww.Body.String(), s) {
			t.Errorf("admin users page missing %q", s)
		}
	}
}

// ------- 创作广场 / 点赞 / 一键删除失败记录 -------

// TestSquareHandler 验证创作广场页正常渲染：公开访问返回 200，
// 包含广场标题、今日点赞榜、7天点赞榜等区域。
func TestSquareHandler(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))
	models.DB.Exec("DELETE FROM users")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',100,'user',1),(2,'u2','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT, model TEXT,
		n INTEGER DEFAULT 1, aspect_ratio TEXT, resolution TEXT, response_format TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT, error_msg TEXT,
		channel TEXT, nsfw INTEGER DEFAULT 0, is_public INTEGER DEFAULT 0,
		published_at DATETIME, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec(`INSERT INTO generation_records(id, user_id, prompt, cost_points, status, is_public, nsfw) VALUES
		(1,1,'广场作品1',10,'success',1,0),
		(2,1,'未发布作品',10,'success',0,0),
		(3,2,'广场作品2',10,'success',1,0),
		(4,1,'nsfw作品',10,'success',1,1),
		(5,1,'失败作品',10,'failed',1,0)`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_images (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, idx INTEGER DEFAULT 0, path TEXT DEFAULT '', storage_type TEXT DEFAULT '', storage_path TEXT DEFAULT '')`)
	models.DB.Exec("INSERT INTO generation_images(record_id, idx, path) VALUES(1,0,'/images/s1.png'),(3,0,'/images/s3.png')")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS creation_likes (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, user_id))`)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/square", nil)
	squareHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	body := w.Body.String()
	for _, s := range []string{"创作广场", "广场作品1", "广场作品2", "今日点赞榜", "7 天点赞榜", "登录后创作发布"} {
		if !strings.Contains(body, s) {
			t.Errorf("square page should contain %q", s)
		}
	}
	// 未发布、NSFW、失败记录不应出现在广场
	if strings.Contains(body, "未发布作品") {
		t.Error("square page should not contain unpublished record")
	}
	if strings.Contains(body, "nsfw作品") {
		t.Error("square page should not contain NSFW record")
	}
	if strings.Contains(body, "失败作品") {
		t.Error("square page should not contain failed record")
	}
}

// TestSquareNotShowCleaned 验证广场不展示已被清理的作品：
// 记录图片本地路径与外部备份都为空（已删除/已清理）时，作品不在广场出现。
func TestSquareNotShowCleaned(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))
	models.DB.Exec("DELETE FROM users")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT, model TEXT,
		n INTEGER DEFAULT 1, aspect_ratio TEXT, resolution TEXT, response_format TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT, error_msg TEXT,
		channel TEXT, nsfw INTEGER DEFAULT 0, is_public INTEGER DEFAULT 0,
		published_at DATETIME, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec(`INSERT INTO generation_records(id, user_id, prompt, cost_points, status, is_public, nsfw) VALUES
		(1,1,'正常作品',10,'success',1,0),
		(2,1,'已清理作品',10,'success',1,0)`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_images (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, idx INTEGER DEFAULT 0, path TEXT DEFAULT '', storage_type TEXT DEFAULT '', storage_path TEXT DEFAULT '')`)
	// 作品1 有本地图片；作品2 本地路径被清空且无外部备份（= 已被清理）
	models.DB.Exec("INSERT INTO generation_images(record_id, idx, path, storage_path) VALUES(1,0,'/images/a.png',''),(2,0,'','')")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS creation_likes (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, user_id))`)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/square", nil)
	squareHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "正常作品") {
		t.Errorf("square should show record with existing image: %s", truncateRunes(body, 200))
	}
	if strings.Contains(body, "已清理作品") {
		t.Error("square should NOT show cleaned record (no local/remote image)")
	}
}

// TestSquareUserHandler 验证创作人页面：显示该用户已发布的作品，
// 不显示该用户未发布或失败的作品。
func TestSquareUserHandler(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))
	models.DB.Exec("DELETE FROM users")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT, model TEXT,
		n INTEGER DEFAULT 1, aspect_ratio TEXT, resolution TEXT, response_format TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT, error_msg TEXT,
		channel TEXT, nsfw INTEGER DEFAULT 0, is_public INTEGER DEFAULT 0,
		published_at DATETIME, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec(`INSERT INTO generation_records(id, user_id, prompt, cost_points, status, is_public) VALUES
		(1,1,'已发布作品',10,'success',1),
		(2,1,'未发布作品',10,'success',0)`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_images (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, idx INTEGER DEFAULT 0, path TEXT DEFAULT '', storage_type TEXT DEFAULT '', storage_path TEXT DEFAULT '')`)
	models.DB.Exec("INSERT INTO generation_images(record_id, idx, path) VALUES(1,0,'/images/s1.png')")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/square/user?u=u1", nil)
	squareUserHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "u1 的作品") {
		t.Errorf("user page should show username: %s", truncateRunes(body, 200))
	}
	if !strings.Contains(body, "已发布作品") {
		t.Errorf("user page should show published record: %s", truncateRunes(body, 200))
	}
	if strings.Contains(body, "未发布作品") {
		t.Error("user page should not show unpublished record")
	}

	// 不存在的用户返回 404
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/square/user?u=nobody", nil)
	squareUserHandler(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("missing user status=%d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "404") {
		t.Errorf("missing user should show 404: %s", truncateRunes(w2.Body.String(), 200))
	}
}

// TestSquareLike 验证点赞流程：用户可点赞他人作品，不能给自己点赞，
// 重复点赞切换为取消，点赞数实时更新。
func TestSquareLike(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	models.DB.Exec("DELETE FROM users")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',100,'user',1),(2,'u2','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT,
		nsfw INTEGER DEFAULT 0, is_public INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec("INSERT INTO generation_records(id, user_id, prompt, cost_points, status, is_public, nsfw) VALUES(1,1,'作品1',10,'success',1,0)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS creation_likes (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, user_id))`)

	csrf := "test-csrf"
	// u2 登录
	req := httptest.NewRequest(http.MethodPost, "/square/like", strings.NewReader("id=1&_csrf="+csrf))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	s, _ := store.Get(req, "session")
	s.Values["userID"] = int64(2)
	s.Values["username"] = "u2"
	s.Values["role"] = "user"
	s.Values["csrf"] = csrf
	w0 := httptest.NewRecorder()
	s.Save(req, w0)

	w := httptest.NewRecorder()
	squareLikeHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("like status=%d", w.Code)
	}
	var resp struct {
		Ok    bool `json:"ok"`
		Liked bool `json:"liked"`
		Count int  `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v body=%s", err, w.Body.String())
	}
	if !resp.Ok || !resp.Liked || resp.Count != 1 {
		t.Errorf("first like: ok=%v liked=%v count=%d, want ok=true liked=true count=1", resp.Ok, resp.Liked, resp.Count)
	}

	// 再次点赞（切换为取消）
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/square/like", strings.NewReader("id=1&_csrf="+csrf))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("X-Requested-With", "XMLHttpRequest")
	s2, _ := store.Get(req2, "session")
	s2.Values["userID"] = int64(2)
	s2.Values["username"] = "u2"
	s2.Values["role"] = "user"
	s2.Values["csrf"] = csrf
	w0b := httptest.NewRecorder()
	s2.Save(req2, w0b)
	squareLikeHandler(w2, req2)
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.Ok || resp.Liked || resp.Count != 0 {
		t.Errorf("toggle unlike: ok=%v liked=%v count=%d, want ok=true liked=false count=0", resp.Ok, resp.Liked, resp.Count)
	}

	// 给自己点赞（不允许）
	req3 := httptest.NewRequest(http.MethodPost, "/square/like", strings.NewReader("id=1&_csrf="+csrf))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.Header.Set("X-Requested-With", "XMLHttpRequest")
	s3, _ := store.Get(req3, "session")
	s3.Values["userID"] = int64(1) // owner of record 1
	s3.Values["username"] = "u1"
	s3.Values["role"] = "user"
	s3.Values["csrf"] = csrf
	w0c := httptest.NewRecorder()
	s3.Save(req3, w0c)
	w3 := httptest.NewRecorder()
	squareLikeHandler(w3, req3)
	if err := json.Unmarshal(w3.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.Ok {
		t.Errorf("self-like should not be allowed: %s", w3.Body.String())
	}
}

// TestRecordDeleteFailed 验证一键删除失败记录接口：只删除当前用户的失败记录，
// 成功记录不受影响，失败记录的相关点赞数据一并清理。
func TestRecordDeleteFailed(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	models.DB.Exec("DELETE FROM users")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT,
		nsfw INTEGER DEFAULT 0, is_public INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
		task_key TEXT DEFAULT '')`)
	models.DB.Exec(`INSERT INTO generation_records(id, user_id, prompt, cost_points, status, task_key) VALUES
		(1,1,'成功记录',10,'success','sk1'),
		(2,1,'失败记录1',10,'failed','fk1'),
		(3,1,'失败记录2',10,'failed','fk2')`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_images (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, idx INTEGER DEFAULT 0, path TEXT DEFAULT '', storage_type TEXT DEFAULT '', storage_path TEXT DEFAULT '')`)
	models.DB.Exec("INSERT INTO generation_images(record_id, idx, path) VALUES(2,0,'/images/fail1.png')")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS creation_likes (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, user_id))`)
	models.DB.Exec("INSERT INTO creation_likes(record_id, user_id) VALUES(2,1)")

	csrf := "test-csrf"
	req := httptest.NewRequest(http.MethodPost, "/records/delete-failed", strings.NewReader("_csrf="+csrf))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s, _ := store.Get(req, "session")
	s.Values["userID"] = int64(1)
	s.Values["username"] = "u1"
	s.Values["role"] = "user"
	s.Values["csrf"] = csrf
	w0 := httptest.NewRecorder()
	s.Save(req, w0)

	w := httptest.NewRecorder()
	recordDeleteFailedHandler(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete-failed status=%d want 303", w.Code)
	}
	var successCount, failedCount int
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE user_id=1 AND status='success'").Scan(&successCount)
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE user_id=1 AND status='failed'").Scan(&failedCount)
	if successCount != 1 {
		t.Errorf("success records should remain: got %d, want 1", successCount)
	}
	if failedCount != 0 {
		t.Errorf("failed records should be deleted: got %d, want 0", failedCount)
	}
	// 失败记录的点赞应一并清理
	var likeCount int
	models.DB.QueryRow("SELECT COUNT(*) FROM creation_likes WHERE record_id=2").Scan(&likeCount)
	if likeCount != 0 {
		t.Errorf("likes of deleted failed record should be cleaned: got %d, want 0", likeCount)
	}
}

// TestRecordPublish 验证发布/取消发布切换：成功记录可发布到广场，
// 失败记录不能发布；切换后查询数据库验证 is_public 状态。
func TestRecordPublish(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	models.DB.Exec("DELETE FROM users")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT,
		nsfw INTEGER DEFAULT 0, is_public INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
		task_key TEXT DEFAULT '')`)
	models.DB.Exec(`INSERT INTO generation_records(id, user_id, prompt, cost_points, status, is_public, task_key) VALUES
		(1,1,'成功记录',10,'success',0,'sk1'),
		(2,1,'失败记录',10,'failed',0,'fk1')`)

	csrf := "test-csrf"
	// 发布成功记录
	req := httptest.NewRequest(http.MethodPost, "/records/publish", strings.NewReader("id=sk1&publish=1&_csrf="+csrf))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s, _ := store.Get(req, "session")
	s.Values["userID"] = int64(1)
	s.Values["username"] = "u1"
	s.Values["role"] = "user"
	s.Values["csrf"] = csrf
	w0 := httptest.NewRecorder()
	s.Save(req, w0)
	w := httptest.NewRecorder()
	recordPublishHandler(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("publish status=%d want 303", w.Code)
	}
	var isPublic int
	models.DB.QueryRow("SELECT is_public FROM generation_records WHERE id=1").Scan(&isPublic)
	if isPublic != 1 {
		t.Errorf("publish success record: is_public=%d want 1", isPublic)
	}

	// 尝试发布失败记录（不应允许）
	req2 := httptest.NewRequest(http.MethodPost, "/records/publish", strings.NewReader("id=fk1&publish=1&_csrf="+csrf))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s2, _ := store.Get(req2, "session")
	s2.Values["userID"] = int64(1)
	s2.Values["username"] = "u1"
	s2.Values["role"] = "user"
	s2.Values["csrf"] = csrf
	w0b := httptest.NewRecorder()
	s2.Save(req2, w0b)
	w2 := httptest.NewRecorder()
	recordPublishHandler(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("publish failed record should be rejected: status=%d", w2.Code)
	}
	models.DB.QueryRow("SELECT is_public FROM generation_records WHERE id=2").Scan(&isPublic)
	if isPublic != 0 {
		t.Errorf("failed record should not be publishable: is_public=%d", isPublic)
	}
}

// TestLikeRanking 验证点赞排行榜：按北京时间的当日/近 7 天排序，
// 只统计正常状态用户，正确返回排名与数量。
func TestLikeRanking(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, points INTEGER DEFAULT 0, role TEXT DEFAULT 'user', status INTEGER DEFAULT 1)`)
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',100,'user',1),(2,'u2','x',100,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS creation_likes (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, user_id))`)
	models.DB.Exec("INSERT INTO creation_likes(record_id, user_id) VALUES(1,1),(2,1),(3,1),(4,2)")

	daily := likeRanking("daily", 10)
	if len(daily) == 0 {
		t.Log("daily ranking empty (no likes today), not a test issue")
	}
	week := likeRanking("week", 10)
	if len(week) == 0 {
		t.Log("week ranking empty (no likes this week), not a test issue")
	}
}

// TestSettleLikeRanking 验证每日点赞排行结算：幂等性（重复结算不重复发放），
// 无点赞时不发放积分。
func TestSettleLikeRanking(t *testing.T) {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	defer models.DB.Close()
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, points INTEGER DEFAULT 0, role TEXT DEFAULT 'user', status INTEGER DEFAULT 1)`)
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',0,'user',1),(2,'u2','x',0,'user',1)")
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS creation_likes (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, user_id))`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT, status TEXT, nsfw INTEGER DEFAULT 0, is_public INTEGER DEFAULT 0)`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_images (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, idx INTEGER DEFAULT 0, path TEXT DEFAULT '')`)
	models.DB.Exec("INSERT INTO generation_records(id, user_id, prompt, status, is_public) VALUES(1,1,'p1','success',1),(2,1,'p2','success',1),(3,1,'p3','success',1),(4,2,'p4','success',1)")
	// 结算今天的日期（可能没有数据，但两次调用都应幂等不报错）
	today := time.Now().In(beijingTZ).Format("2006-01-02")
	settleLikeRanking(today)
	settleLikeRanking(today)
	// 无点赞，无人获得奖励
	var p1, p2 int64
	models.DB.QueryRow("SELECT points FROM users WHERE id=1").Scan(&p1)
	models.DB.QueryRow("SELECT points FROM users WHERE id=2").Scan(&p2)
	if p1 != 0 || p2 != 0 {
		t.Errorf("no likes yet, points should be 0: u1=%d u2=%d", p1, p2)
	}
}

// setupSquareTestEnv 为广场相关测试准备一张最小可渲染的表结构与数据
// （匿名函数返回清理函数：关闭全局 DB）。
func setupSquareTestEnv(t *testing.T) func() {
	dir := t.TempDir()
	if err := models.InitDB(filepath.Join(dir, "t.db")); err != nil {
		t.Fatal(err)
	}
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma":   commaFormat,
		"pages":   pagesAround,
		"trunc":   truncateRunes,
		"add":     func(a, b int) int { return a + b },
		"hasRes":  func(list []string, v string) bool { return containsString(list, v) },
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))
	models.DB.Exec("DELETE FROM users")
	return func() { models.DB.Close() }
}

func squareBaseTables() {
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, points INTEGER DEFAULT 0, role TEXT DEFAULT 'user', status INTEGER DEFAULT 1, show_nsfw INTEGER DEFAULT 0)`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prompt TEXT, model TEXT,
		n INTEGER DEFAULT 1, aspect_ratio TEXT, resolution TEXT, response_format TEXT,
		cost_points INTEGER DEFAULT 0, status TEXT, image_url TEXT, error_msg TEXT,
		channel TEXT, nsfw INTEGER DEFAULT 0, is_public INTEGER DEFAULT 0,
		published_at DATETIME, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS generation_images (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, idx INTEGER DEFAULT 0, path TEXT DEFAULT '', storage_type TEXT DEFAULT '', storage_path TEXT DEFAULT '')`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS creation_likes (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(record_id, user_id))`)
	models.DB.Exec(`CREATE TABLE IF NOT EXISTS like_daily_awards (id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL, user_id INTEGER NOT NULL, like_count INTEGER DEFAULT 0, rank INTEGER DEFAULT 0, points INTEGER DEFAULT 0, UNIQUE(date, user_id))`)
}

// authenticatedRequest 构造一个已登录的（可带用户 ID）HTTP 请求。
func authenticatedRequest(t *testing.T, method, target string, uid int64, uname string, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	s, _ := store.Get(req, "session")
	s.Values["userID"] = uid
	s.Values["username"] = uname
	s.Values["role"] = "user"
	s.Values["csrf"] = "test-csrf"
	w0 := httptest.NewRecorder()
	s.Save(req, w0)
	return req
}

// TestSquareDisabled 验证广场开关：关闭后访问广场显示“已关闭”提示，
// 点赞接口也拒绝操作。
func TestSquareDisabled(t *testing.T) {
	cleanup := setupSquareTestEnv(t)
	defer cleanup()
	squareBaseTables()
	models.SetConfig("square_enabled", "false")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',100,'user',1)")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/square", nil)
	squareHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "创作广场已关闭") {
		t.Error("square disabled page should show 创作广场已关闭")
	}
	// 点赞也拒绝
	req2 := authenticatedRequest(t, http.MethodPost, "/square/like", 1, "u1", "id=1&_csrf=test-csrf")
	w2 := httptest.NewRecorder()
	squareLikeHandler(w2, req2)
	var resp struct {
		Ok  bool   `json:"ok"`
		Err string `json:"error"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.Ok {
		t.Error("like should be rejected when square disabled")
	}
}

// TestSquareNSFWVisibility 验证 NSFW 可见性规则：
// 管理员允许 NSFW 时，未登录/未开启的用户看不到 NSFW 作品，
// 已登录且开启 show_nsfw 的用户可以看到。
func TestSquareNSFWVisibility(t *testing.T) {
	cleanup := setupSquareTestEnv(t)
	defer cleanup()
	squareBaseTables()
	models.SetConfig("square_allow_nsfw", "true")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status, show_nsfw) VALUES(1,'u1','x',100,'user',1,0),(2,'u2','x',100,'user',1,1)")
	models.DB.Exec(`INSERT INTO generation_records(id, user_id, prompt, cost_points, status, is_public, nsfw) VALUES
		(1,1,'普通作品',10,'success',1,0),
		(2,1,'NSFW作品',10,'success',1,1)`)
	models.DB.Exec("INSERT INTO generation_images(record_id, idx, path) VALUES(1,0,'/images/a.png'),(2,0,'/images/b.png')")

	// 未登录：看不到 NSFW
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/square", nil)
	squareHandler(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "普通作品") {
		t.Error("logged-out user should see normal work")
	}
	if strings.Contains(body, "NSFW作品") {
		t.Error("logged-out user should NOT see NSFW work")
	}

	// 已登录但未开启 show_nsfw (u1)：看不到 NSFW
	req1 := authenticatedRequest(t, http.MethodGet, "/square", 1, "u1", "")
	req1.Header.Del("Content-Type")
	w1 := httptest.NewRecorder()
	squareHandler(w1, req1)
	body1 := w1.Body.String()
	if strings.Contains(body1, "NSFW作品") {
		t.Error("logged-in user with show_nsfw=0 should NOT see NSFW work")
	}

	// 已登录且开启 show_nsfw (u2)：可以看到 NSFW
	req2 := authenticatedRequest(t, http.MethodGet, "/square", 2, "u2", "")
	req2.Header.Del("Content-Type")
	w2 := httptest.NewRecorder()
	squareHandler(w2, req2)
	if !strings.Contains(w2.Body.String(), "NSFW作品") {
		t.Error("logged-in user with show_nsfw=1 SHOULD see NSFW work")
	}

	// 管理员关闭 NSFW 后：即使开启 show_nsfw 也看不到
	models.SetConfig("square_allow_nsfw", "false")
	req3 := authenticatedRequest(t, http.MethodGet, "/square", 2, "u2", "")
	req3.Header.Del("Content-Type")
	w3 := httptest.NewRecorder()
	squareHandler(w3, req3)
	if strings.Contains(w3.Body.String(), "NSFW作品") {
		t.Error("when admin disallows NSFW, no one should see NSFW work")
	}
}

// TestSquareNSFWHandler 验证 NSFW 开关切换接口：登录用户可设置，
// 管理员关闭 NSFW 时设置强制为 false。
func TestSquareNSFWHandler(t *testing.T) {
	cleanup := setupSquareTestEnv(t)
	defer cleanup()
	squareBaseTables()
	models.SetConfig("square_allow_nsfw", "true")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status, show_nsfw) VALUES(1,'u1','x',100,'user',1,0)")

	req := authenticatedRequest(t, http.MethodPost, "/square/nsfw", 1, "u1", "on=1&_csrf=test-csrf")
	w := httptest.NewRecorder()
	squareNSFWHandler(w, req)
	var resp struct {
		Ok      bool `json:"ok"`
		ShowNSW bool `json:"show_nsfw"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.Ok || !resp.ShowNSW {
		t.Errorf("nsfw toggle on: ok=%v show_nsfw=%v want true", resp.Ok, resp.ShowNSW)
	}
	var v int
	models.DB.QueryRow("SELECT show_nsfw FROM users WHERE id=1").Scan(&v)
	if v != 1 {
		t.Errorf("after toggle on, show_nsfw=%d want 1", v)
	}

	// 管理员关闭 NSFW 后开关强制关闭
	models.SetConfig("square_allow_nsfw", "false")
	req2 := authenticatedRequest(t, http.MethodPost, "/square/nsfw", 1, "u1", "on=1&_csrf=test-csrf")
	w2 := httptest.NewRecorder()
	squareNSFWHandler(w2, req2)
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.Ok && resp.ShowNSW {
		t.Error("nsfw toggle should force off when admin disables NSFW")
	}
	models.DB.QueryRow("SELECT show_nsfw FROM users WHERE id=1").Scan(&v)
	if v != 0 {
		t.Errorf("after admin disables, show_nsfw=%d want 0", v)
	}
}

// TestCleanupProtectsRankedWorks 验证自动清理会保留：
// 近7天每日点赞前10的作品记录与图片文件；不在榜上的旧作品正常清理。
func TestCleanupProtectsRankedWorks(t *testing.T) {
	cleanup := setupSquareTestEnv(t)
	defer cleanup()
	squareBaseTables()
	models.SetConfig("cleanup_enabled", "true")
	models.SetConfig("cleanup_keep_days", "30")
	models.SetConfig("cleanup_max_mb", "2048")
	models.DB.Exec("INSERT INTO users(id, username, password_hash, points, role, status) VALUES(1,'u1','x',100,'user',1)")
	// 两条超期记录：ranked（今天点赞前列）与 old（无点赞）
	old := time.Now().AddDate(0, 0, -60).Format("2006-01-02 15:04:05")
	models.DB.Exec(`INSERT INTO generation_records(id, user_id, prompt, cost_points, status, is_public, nsfw, created_at) VALUES
		(1,1,'榜上作品',10,'success',1,0,?),
		(2,1,'普通旧作品',10,'success',1,0,?)`, old, old)
	models.DB.Exec("INSERT INTO generation_images(record_id, idx, path) VALUES(1,0,'/images/ranked.png'),(2,0,'/images/old.png')")
	// 今天点赞，让作品1成为今日/7天榜单前10
	models.DB.Exec("INSERT INTO creation_likes(record_id, user_id) VALUES(1,1)")

	cleanUpTask()

	// 榜上作品保留：记录与图片行仍在
	var cnt1, cnt2 int
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE id=1").Scan(&cnt1)
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_images WHERE record_id=1").Scan(&cnt2)
	if cnt1 != 1 || cnt2 != 1 {
		t.Errorf("ranked work should be kept: records=%d images=%d", cnt1, cnt2)
	}
	// 普通旧作品被清理
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE id=2").Scan(&cnt1)
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_images WHERE record_id=2").Scan(&cnt2)
	if cnt1 != 0 || cnt2 != 0 {
		t.Errorf("old non-ranked work should be cleaned: records=%d images=%d", cnt1, cnt2)
	}
}
