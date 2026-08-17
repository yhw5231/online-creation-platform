package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"online-creation-platform/models"
	"online-creation-platform/services"
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
		{"0", 1, 1},      // non-positive falls back to default
		{"-3", 1, 1},     // negative falls back to default
		{"abc", 1, 1},    // non-numeric falls back
		{"", 8, 8},       // empty falls back
		{"  5 ", 1, 1},   // whitespace not parsed by Atoi
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
// 其他 IP 不受影响，GET 请求不计数。
func TestRateLimit(t *testing.T) {
	h := rateLimited(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	post := func(ip string) int {
		ww := httptest.NewRecorder()
		rr := httptest.NewRequest(http.MethodPost, "/", nil)
		rr.RemoteAddr = ip
		h(ww, rr)
		return ww.Code
	}
	for i := 0; i < rateLimitPerIP; i++ {
		if code := post("203.0.113.9:1234"); code != http.StatusOK {
			t.Fatalf("request %d blocked early: %d", i+1, code)
		}
	}
	if code := post("203.0.113.9:1234"); code != http.StatusTooManyRequests {
		t.Errorf("over-limit request = %d, want 429", code)
	}
	if code := post("198.51.100.7:1"); code != http.StatusOK {
		t.Errorf("other IP should pass, got %d", code)
	}
	// GET 不计入限流
	ww := httptest.NewRecorder()
	rr := httptest.NewRequest(http.MethodGet, "/", nil)
	rr.RemoteAddr = "203.0.113.9:1234"
	h(ww, rr)
	if ww.Code != http.StatusOK {
		t.Errorf("GET should bypass limiter, got %d", ww.Code)
	}
	// 窗口过期后恢复
	rateLimiter.Lock()
	delete(rateLimiter.hits, "203.0.113.9")
	rateLimiter.Unlock()
	if code := post("203.0.113.9:1234"); code != http.StatusOK {
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
	// parseable UTC -> returns a non-empty localized string (not raw passthrough unless tz is UTC)
	if out := localTime("2026-01-02 15:04:05"); out == "not-a-time" {
		t.Fatal("unreachable")
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
		inMin, inMax string
		wantMin,     wantMax string
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
		"open_registration": "true", "enable_password_registration": "false",
		"enable_thirdparty_registration": "true", "require_reg_code": "true",
		"initial_points": "50", "enable_daily_checkin": "false",
		"checkin_mode": "random", "checkin_fixed_points": "7",
		"checkin_random_min": "3", "checkin_random_max": "9",
		"enable_thirdparty_login": "true", "linuxdo_client_id": "demo-client-id",
		"linuxdo_client_secret": "demo-secret",
		"linuxdo_redirect_uri":  "https://auth.example.com/cb",
		"storage_type": "s3", "storage_endpoint": "https://oss.example.com",
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
// 旧版通用码（kind=''）两者皆可用。
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
			"_csrf":           {regCSRF},
			"username":        {username},
			"password":        {"123456"},
			"confirm_password": {"123456"},
			"reg_code":        {code},
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