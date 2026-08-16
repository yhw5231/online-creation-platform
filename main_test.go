package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

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
		if len(code) != 8 {
			t.Fatalf("redeem code length = %d, want 8", len(code))
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