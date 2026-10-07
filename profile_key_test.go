package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"online-creation-platform/models"
)

// TestProfileNewAPIKeyDisplayAndCopy 验证个人主页对新生成 API Key 的展示：
// 1) 明文完整显示在 readonly 输入框中，并带复制按钮（data-copy 为明文）；
// 2) 提供明文 / 遮蔽切换按钮；
// 3) 明文只显示一次，刷新后不再出现。
func TestProfileNewAPIKeyDisplayAndCopy(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "profilekey.db")); err != nil {
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

	res, err := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)",
		"keyuser", "x", 100, "user", 1)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()

	const plain = "sk-abcdefghijklmnopqrstuvwxyz0123456789"

	// 第一次请求：写入登录态与新 Key
	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	w := httptest.NewRecorder()
	sess, err := store.New(req, "session")
	if err != nil {
		t.Fatal(err)
	}
	sess.Values["userID"] = uid
	sess.Values["username"] = "keyuser"
	sess.Values["role"] = "user"
	sess.Values["new_api_key"] = plain
	if err := sess.Save(req, w); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req2.Header.Set("Cookie", lastCookie(w))
	w2 := httptest.NewRecorder()
	profileHandler(w2, req2)
	body := w2.Body.String()
	if w2.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w2.Code, body)
	}
	for _, want := range []string{
		`id="newApiKeyBox"`,
		`id="newApiKeyValue"`,
		`value="` + plain + `"`,
		`data-copy="` + plain + `"`,
		`class="btn btn-sm btn-warning copy-btn"`,
		`id="newApiKeyToggle"`,
		// 接入说明：一键复制区块 + 自动填入刚生成的 Key
		`id="agentBrief"`,
		`data-copy-target="#agentBrief"`,
		`http://example.com`,
		`Authorization: Bearer ` + plain,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("个人主页缺少 %q", want)
		}
	}

	// 第二次请求：明文已被消费，不应再次出现（接入说明退化为占位符）
	req3 := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req3.Header.Set("Cookie", lastCookie(w2))
	w3 := httptest.NewRecorder()
	profileHandler(w3, req3)
	again := w3.Body.String()
	if strings.Contains(again, plain) {
		t.Error("API Key 明文不应在刷新后再次显示")
	}
	if !strings.Contains(again, "sk-在此填入你的APIKey") {
		t.Error("未生成新 Key 时接入说明应使用 Key 占位符")
	}
}

// TestAPIDocsAgentBriefCopy 验证 API 文档页同样提供可一键复制给智能体的接入
// 说明（未登录 / 未生成 Key 时使用占位符）。
func TestAPIDocsAgentBriefCopy(t *testing.T) {
	if err := models.InitDB(filepath.Join(t.TempDir(), "apidocs.db")); err != nil {
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

	w := httptest.NewRecorder()
	apiDocsHandler(w, httptest.NewRequest(http.MethodGet, "/api/docs", nil))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, body)
	}
	for _, want := range []string{
		`id="agentBrief"`,
		`data-copy-target="#agentBrief"`,
		`sk-在此填入你的APIKey`,
		`http://example.com/v1/images/generations`,
		`X-API-Key`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("API 文档页缺少 %q", want)
		}
	}
}
