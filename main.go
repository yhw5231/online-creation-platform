package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"online-creation-platform/models"
	"online-creation-platform/services"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var (
	store = sessions.NewCookieStore(sessionKey())
	tpl   *template.Template

	// AppVersion 是当前程序版本号（vX.Y.Z）。仓库根目录 VERSION 文件是唯一
	// 版本来源：每次推送到 master 时 CI（.github/workflows/docker-publish.yml）
	// 自动把 VERSION 与这里的内置默认值同步 +1（补丁号）并回写仓库；发布
	// （ghcr 镜像 / 原生安装包）时通过 -ldflags "-X main.AppVersion=..." 注入
	// 同一版本号，保证"文件内版本号"与发布版本、镜像内版本号始终一致。
	// 本地构建请使用 build.sh / build.bat（优先读取 VERSION 文件）。
	AppVersion = "v1.3.1"
	// uploader 按后台"存储设置"构造的外部长期存储上传器（s3/webdav/post）；
	// 未配置时为 nil，图片只存服务器本地。
	// 注意：设置保存/重置（HTTP 请求线程）与生成 worker（后台线程）会并发
	// 读写该全局变量，必须经 uploaderMu 保护（接口值为两个字，非原子读）。
	uploaderMu sync.RWMutex
	uploader   services.Uploader
	// taskQueue 接收新提交的生成任务（记录 ID），由后台 worker 依次消费，
	// 使"开始创作"立即返回，生成过程异步进行、前端轮询同步状态。
	taskQueue = make(chan genTask, 256)
)

// getUploader 并发安全地读取当前外部存储上传器（可能为 nil）。
func getUploader() services.Uploader {
	uploaderMu.RLock()
	defer uploaderMu.RUnlock()
	return uploader
}

// setUploader 并发安全地替换外部存储上传器（设置保存/重置后调用）。
func setUploader(u services.Uploader) {
	uploaderMu.Lock()
	uploader = u
	uploaderMu.Unlock()
}

// genTask 是异步生成队列中的一个待处理任务。
type genTask struct {
	recordID int64
}

// GenerationEndpoint 描述图片生成服务的一个渠道（多接口列表中的一项）。
// Resolutions 为该渠道支持的分辨率档位（如 1k/2k/4k）；未配置或配置为空时
// 视为不限制（默认按 1k/2k 提供选项）。
// Models 为该渠道"可用模型"列表（创作界面按渠道展示、可切换）；未配置时
// 默认提供 defaultModels 快捷选项。
// ID 为该渠道的**稳定编号**：创建时分配、持久化保存，之后渠道增删或调整
// 顺序都不会改变已有编号。网页创作与 API 的 channel 参数均按此编号引用
// 渠道（而不是数组下标），避免渠道列表变动导致调用方选错渠道。
type GenerationEndpoint struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	APIURL      string   `json:"api_url"`
	APIKey      string   `json:"api_key"`
	Model       string   `json:"model"`
	Models      []string `json:"models,omitempty"`
	NSFW        bool     `json:"nsfw"`
	Resolutions []string `json:"resolutions,omitempty"`
}

// defaultResolutions 是渠道未配置分辨率档位时的默认选项。
var defaultResolutions = []string{"1k", "2k"}

// defaultModels 是渠道未配置可用模型时默认提供的快捷选项
// （与设置页"可用模型"多选框选项一致）。
var defaultModels = []string{
	"grok-imagine-image-lite",
	"grok-imagine-image",
	"grok-imagine-image-edit",
	"grok-imagine-image-2.0",
	"grok-imagine-video",
	"gpt-image-2",
}

// sessionKeyPath is where a generated signing key is persisted; a package
// variable so tests can redirect it to a temp location.
var sessionKeyPath = "data/.session_secret"

// sessionKey returns the session signing key. It prefers the SESSION_SECRET
// environment variable (>=16 bytes). Without it, a random 32-byte key is
// generated once, persisted under sessionKeyPath, and reused on every
// restart — so the hardcoded fallback below is never used in practice.
func sessionKey() []byte {
	if k := os.Getenv("SESSION_SECRET"); len(k) >= 16 {
		return []byte(k)
	}
	if b, err := os.ReadFile(sessionKeyPath); err == nil && len(b) >= 32 {
		return b
	}
	os.MkdirAll("data", 0o755)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err == nil {
		if err := os.WriteFile(sessionKeyPath, b, 0o600); err == nil {
			return b
		} else {
			log.Printf("WARN: cannot persist session key at %s (%v); using in-memory key", sessionKeyPath, err)
		}
	}
	log.Printf("WARN: falling back to built-in session key; please set SESSION_SECRET")
	return []byte("super-secret-key-change-me")
}

// sessionSecretDefault reports whether the runtime relies on a weak signing
// key (no env var and no persisted random key) — which should never happen
// in practice, since sessionKey() seeds the file before returning.
func sessionSecretDefault() bool {
	if len(os.Getenv("SESSION_SECRET")) >= 16 {
		return false
	}
	_, err := os.ReadFile(sessionKeyPath)
	return err != nil
}

// csrfToken returns the per-session CSRF token, generating & persisting it on first use.
func csrfToken(w http.ResponseWriter, r *http.Request) string {
	session, _ := store.Get(r, "session")
	tok, _ := session.Values["csrf"].(string)
	if tok == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err == nil {
			tok = hex.EncodeToString(b)
			session.Values["csrf"] = tok
			session.Save(r, w)
		}
	}
	return tok
}

// verifyCSRF checks a submitted CSRF token against the session value.
func verifyCSRF(r *http.Request) bool {
	session, _ := store.Get(r, "session")
	tok, _ := session.Values["csrf"].(string)
	return tok != "" && secureCompare(tok, r.FormValue("_csrf"))
}

// ajaxRequest 判断请求是否由前端异步（fetch）提交：异步请求出错时后端返回
// JSON，由前端原地展示错误，不再整页刷新/重渲染。
func ajaxRequest(r *http.Request) bool {
	return r.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

// writeJSON 输出 JSON 响应（异步表单接口统一出口）。
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// formFail 是注册类表单（普通注册 / Linux.do 完善账号）校验失败的统一出口：
// 异步请求返回 JSON（http 200，字段级错误由前端原地显示、不刷新页面）；
// 普通请求保持原有整页重渲染行为（render 回调）。
func formFail(w http.ResponseWriter, r *http.Request, render func(http.ResponseWriter, *http.Request, string, string, string, string), formErr, codeErr, next, username string) {
	if ajaxRequest(r) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "form": formErr, "reg_code": codeErr})
		return
	}
	render(w, r, formErr, codeErr, next, username)
}

// consumeToken verifies a per-action token against the session and consumes
// it. The token is cleared on first successful use, so a form POST (e.g. the
// image generation) can only be submitted once — refreshing the result page
// can never re-trigger a repeat billing.
func consumeToken(w http.ResponseWriter, r *http.Request, name string) bool {
	session, _ := store.Get(r, "session")
	tok, _ := session.Values[name].(string)
	sub := r.FormValue("_" + name)
	if tok == "" || !secureCompare(tok, sub) {
		return false
	}
	delete(session.Values, name)
	session.Save(r, w)
	return true
}

// mintToken stores a fresh per-action token in the session and returns it.
func mintToken(w http.ResponseWriter, r *http.Request, name string) string {
	session, _ := store.Get(r, "session")
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	tok := hex.EncodeToString(b)
	session.Values[name] = tok
	session.Save(r, w)
	return tok
}

// secureCompare is a constant-time string comparison.
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ------- Login brute-force throttling -------
const (
	loginMaxAttempts = 5
	loginLockWindow  = 10 * time.Minute
)

var loginGuard = struct {
	sync.Mutex
	fails map[string]*loginFail
}{fails: make(map[string]*loginFail)}

type loginFail struct {
	count int
	until time.Time
}

// clientIP returns the client IP used as the throttle key. When the service
// runs behind a reverse proxy, set TRUST_PROXY_HEADERS=true so the first
// X-Forwarded-For entry is used instead of the proxy address — otherwise all
// visitors share one lockout counter.
func clientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if os.Getenv("TRUST_PROXY_HEADERS") == "true" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ip = strings.TrimSpace(strings.Split(xff, ",")[0])
		} else if xff := r.Header.Get("X-Real-IP"); xff != "" {
			ip = strings.TrimSpace(xff)
		}
	}
	if h, _, err := net.SplitHostPort(ip); err == nil {
		return h
	}
	return ip
}

func isLoginLocked(key string) bool {
	loginGuard.Lock()
	defer loginGuard.Unlock()
	f, ok := loginGuard.fails[key]
	return ok && time.Now().Before(f.until)
}

func recordLoginFail(key string) {
	loginGuard.Lock()
	defer loginGuard.Unlock()
	now := time.Now()
	// 只保留仍处于锁定中的条目，防止失败地址无限累积内存。
	// 当前 key 的累计计数不在清理范围内——若每次失败都被删掉，
	// 计数永远到不了阈值，锁定永远不会触发。
	for k, f := range loginGuard.fails {
		if k == key {
			continue
		}
		if !(f.count >= loginMaxAttempts && now.Before(f.until)) {
			delete(loginGuard.fails, k)
		}
	}
	f, ok := loginGuard.fails[key]
	if !ok {
		f = &loginFail{}
		loginGuard.fails[key] = f
	}
	f.count++
	if f.count >= loginMaxAttempts {
		f.until = now.Add(loginLockWindow)
		log.Printf("login brute-force locked: ip=%s block=%s", key, loginLockWindow)
	}
}

func clearLoginFails(key string) {
	loginGuard.Lock()
	defer loginGuard.Unlock()
	delete(loginGuard.fails, key)
}

// 通用防爆破：按 IP 的滑动窗口限流，覆盖登录/注册/兑换/改密等敏感 POST
// 接口。登录接口除本限流外，另有独立的 5 次失败锁定 10 分钟机制
// （loginMaxAttempts / loginLockWindow）。
const (
	rateLimitWindow = time.Minute
	rateLimitPerIP  = 10 // 每个 IP 每分钟允许的敏感请求数
)

var rateLimiter = struct {
	sync.Mutex
	hits map[string][]time.Time
}{hits: make(map[string][]time.Time)}

// allowRateLimit 对 key（客户端 IP）做滑动窗口计数：窗口内已达上限返回
// false；过期时间戳会被清除，空桶删除以防内存无限增长。
func allowRateLimit(key string, limit int, window time.Duration) bool {
	rateLimiter.Lock()
	defer rateLimiter.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	list := rateLimiter.hits[key]
	kept := list[:0]
	for _, t := range list {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) < limit {
		rateLimiter.hits[key] = append(kept, now)
		return true
	}
	if len(kept) == 0 {
		delete(rateLimiter.hits, key)
	} else {
		rateLimiter.hits[key] = kept
	}
	return false
}

// rateLimited 包裹敏感接口：POST 请求按 IP 限流，超限返回 429。
// 异步请求返回 JSON，前端原地提示，不刷新页面。
func rateLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && !allowRateLimit(clientIP(r), rateLimitPerIP, rateLimitWindow) {
			log.Printf("rate limited: ip=%s path=%s", clientIP(r), r.URL.Path)
			if ajaxRequest(r) {
				writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{"ok": false, "error": "操作过于频繁，请稍后再试"})
				return
			}
			http.Error(w, "操作过于频繁，请稍后再试", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   os.Getenv("COOKIE_SECURE") == "true",
	}
}

func main() {
	if err := models.InitDB("data/creation.db"); err != nil {
		log.Fatal("DB init:", err)
	}
	// 为历史配置中缺失编号的渠道补发稳定编号（幂等迁移）
	migrateEndpointIDs()

	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"comma": commaFormat,
		"pages": pagesAround,
		"trunc": truncateRunes,
		"add": func(a, b int) int {
			return a + b
		},
		"hasRes": func(list []string, v string) bool {
			return containsString(list, v)
		},
		"maskKey": maskKey,
	}).ParseGlob("templates/*.html"))
	tpl = template.Must(tpl.ParseGlob("templates/admin/*.html"))

	// 多接口渠道在生成时按需读取（loadEndpoints），无需全局缓存客户端
	if url, _ := models.GetConfig("generation_api_url"); url == "" {
		log.Println("Warning: generation_api_url or key not set")
	}

	// 启动异步生成 worker：所有新提交的任务在此串行（或按队列）处理
	go generationWorker()
	// 恢复上次运行遗留的进行中任务（进程重启后队列丢失，数据库仍标记 processing）
	recoverPendingTasks()

	// 初始化外部长期存储上传器（s3/webdav/post），未配置时为 nil
	u0 := loadStorageUploader()
	setUploader(u0)
	if u0 != nil {
		log.Println("Storage uploader enabled:", storageTypeOf())
	}
	// 启动自动清理任务：按保留天数 + 按磁盘上限（受后台设置控制）
	go cleanupLoop()

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", rateLimited(loginHandler))
	http.HandleFunc("/register", rateLimited(registerHandler))
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/create", authMiddleware(createHandler))
	http.HandleFunc("/generate", authMiddleware(generateHandler))
	http.HandleFunc("/generate/status", authMiddleware(generateStatusHandler))
	http.HandleFunc("/profile", authMiddleware(profileHandler))
	http.HandleFunc("/records", authMiddleware(recordsHandler))
	http.HandleFunc("/records/delete", authMiddleware(recordDeleteHandler))
	http.HandleFunc("/redeem", authMiddleware(rateLimited(redeemHandler)))
	http.HandleFunc("/checkin", authMiddleware(checkinHandler))
	http.HandleFunc("/points", authMiddleware(pointsHandler))
	http.HandleFunc("/leaderboard", leaderboardHandler)
	http.HandleFunc("/rules", rulesHandler)
	http.HandleFunc("/notices", noticesHandler)
	http.HandleFunc("/admin/notices", authMiddleware(adminMiddleware(adminNoticesHandler)))
	http.HandleFunc("/admin/notice/add", authMiddleware(adminMiddleware(adminNoticeAddHandler)))
	http.HandleFunc("/admin/notice/delete", authMiddleware(adminMiddleware(adminNoticeDeleteHandler)))
	http.HandleFunc("/admin/notice/toggle", authMiddleware(adminMiddleware(adminNoticeToggleHandler)))
	http.HandleFunc("/password", authMiddleware(rateLimited(passwordHandler)))
	http.HandleFunc("/auth/linuxdo", linuxdoHandler)
	http.HandleFunc("/auth/linuxdo/callback", linuxdoCallbackHandler)
	http.HandleFunc("/auth/linuxdo/setup", rateLimited(linuxdoSetupHandler))
	http.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("data/images"))))
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/admin/users", authMiddleware(adminMiddleware(adminUsersHandler)))
	http.HandleFunc("/admin/user/disable", authMiddleware(adminMiddleware(adminUserDisableHandler)))
	http.HandleFunc("/admin/user/enable", authMiddleware(adminMiddleware(adminUserEnableHandler)))
	http.HandleFunc("/admin/user/promote", authMiddleware(adminMiddleware(adminUserPromoteHandler)))
	http.HandleFunc("/admin/user/demote", authMiddleware(adminMiddleware(adminUserDemoteHandler)))
	http.HandleFunc("/admin/user/adjust-points", authMiddleware(adminMiddleware(adminAdjustPointsHandler)))
	http.HandleFunc("/admin/redeem-codes", authMiddleware(adminMiddleware(adminRedeemCodesHandler)))
	http.HandleFunc("/admin/redeem-codes/generate", authMiddleware(adminMiddleware(adminGenerateRedeemCodesHandler)))
	http.HandleFunc("/admin/redeem-codes/void", authMiddleware(adminMiddleware(adminVoidRedeemCodeHandler)))
	http.HandleFunc("/admin/redeem-codes/remark", authMiddleware(adminMiddleware(adminRemarkRedeemCodesHandler)))
	http.HandleFunc("/admin/redeem-codes/void-old", authMiddleware(adminMiddleware(adminVoidOldCodesHandler)))
	http.HandleFunc("/admin/settings", authMiddleware(adminMiddleware(adminSettingsHandler)))
	http.HandleFunc("/admin/logs", authMiddleware(adminMiddleware(adminSystemLogsHandler)))
	http.HandleFunc("/admin/update-settings", authMiddleware(adminMiddleware(adminUpdateSettingsHandler)))
	http.HandleFunc("/admin/reset-settings", authMiddleware(adminMiddleware(adminResetSettingsHandler)))
	http.HandleFunc("/admin/check-update", authMiddleware(adminMiddleware(adminCheckUpdateHandler)))
	http.HandleFunc("/admin/update", authMiddleware(adminMiddleware(adminUpdateHandler)))
	http.HandleFunc("/admin", authMiddleware(adminMiddleware(adminDashboardHandler)))
	http.HandleFunc("/admin/backup", authMiddleware(adminMiddleware(adminBackupHandler)))
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/robots.txt", robotsHandler)

	// API Key 管理（网页登录 + CSRF）与外部调用接口（Key 认证）
	http.HandleFunc("/api/key/generate", authMiddleware(apiKeyGenerateHandler))
	http.HandleFunc("/api/v1/generate", apiAuthMiddleware(apiGenerateHandler))
	http.HandleFunc("/api/v1/status", apiAuthMiddleware(apiStatusHandler))
	http.HandleFunc("/api/v1/channels", apiAuthMiddleware(apiChannelsHandler))
	http.HandleFunc("/api/docs", apiDocsHandler)

	addr := os.Getenv("PORT")
	if addr == "" {
		addr = ":8900"
	} else if !strings.HasPrefix(addr, ":") {
		addr = ":" + addr
	}
	log.Println("Server starting on", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           limitBody(securityHeaders(http.DefaultServeMux), 2<<20),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       90 * time.Second,
	}
	// 优雅关闭：收到退出信号后先停止接收新连接，等待在途请求完成
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			log.Println("Shutdown error:", err)
		}
		log.Println("Server gracefully stopped")
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// limitBody caps the request body on non-GET requests so an oversized form
// payload can never exhaust server memory. Over-limit requests degrade to a
// benign parse failure handled by each handler, not to a crash.
func limitBody(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders adds sensible hardening headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "+
				"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "+
				"img-src 'self' data: https:; font-src 'self' data: https://cdn.jsdelivr.net; "+
				"connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// healthHandler reports process & database health for load balancers and
// container health checks. Returns 200 only when the DB answers.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := models.DB.Ping(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "db": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// robotsHandler keeps search engines out of member-only and admin areas.
func robotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("User-agent: *\n" +
		"Disallow: /admin/\n" +
		"Disallow: /login\n" +
		"Disallow: /register\n" +
		"Disallow: /records\n" +
		"Disallow: /points\n" +
		"Disallow: /checkin\n" +
		"Disallow: /create\n" +
		"Disallow: /profile\n" +
		"Disallow: /password\n" +
		"Disallow: /redeem\n"))
}

// adminBackupHandler streams a consistent snapshot of the SQLite database.
// VACUUM INTO writes a live, consistent copy without stopping the service;
// the temp file is removed right after the download finishes.
func adminBackupHandler(w http.ResponseWriter, r *http.Request) {
	tmp := filepath.Join("data", fmt.Sprintf("backup-%d.db", time.Now().UnixNano()))
	if _, err := models.DB.Exec("VACUUM INTO ?", tmp); err != nil {
		if _, err2 := models.DB.Exec("VACUUM INTO '" + tmp + "'"); err2 != nil {
			http.Error(w, "备份失败："+err2.Error(), http.StatusInternalServerError)
			return
		}
	}
	defer os.Remove(tmp)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=creation-backup-"+time.Now().Format("20060102-150405")+".db")
	http.ServeFile(w, r, tmp)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		render404(w, r)
		return
	}
	session, _ := store.Get(r, "session")
	if userID, ok := session.Values["userID"].(int64); ok && userID > 0 {
		http.Redirect(w, r, "/create", http.StatusSeeOther)
	} else {
		renderHome(w, r)
	}
}

// renderHome renders the landing page for logged-out visitors.
// noStore tells browsers & proxies not to cache HTML pages, so a stale
// logged-in navbar/points badge can never be served from local cache.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

func renderHome(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	// 精选最近几张本地存储的成功作品，让访客先睹为快
	var showcase []map[string]interface{}
	rows, err := models.DB.Query(`SELECT gi.path FROM generation_images gi
		JOIN generation_records gr ON gr.id = gi.record_id
		WHERE gr.status = 'success' AND gi.path LIKE '/images/%'
		ORDER BY gi.id DESC LIMIT 6`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p string
			if rows.Scan(&p) == nil {
				showcase = append(showcase, map[string]interface{}{"Path": p})
			}
		}
	}
	data := map[string]interface{}{
		"Title":        "AI 图片创作平台",
		"IsAdmin":      false,
		"IsLoggedIn":   false,
		"Points":       0,
		"Username":     "",
		"SiteName":     siteName(),
		"OAuthEnabled": oauthEnabled(),
		"Showcase":     showcase,
		"CSRF":         csrfToken(w, r),
		"Toast":        consumeFlash(w, r),
		"Content":      "content-home",
	}
	if err := tpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// checkinAvailable reports whether the user can still sign in today
// (checkin enabled on the site and no log for today yet).
func checkinAvailable(userID int64) bool {
	enabled, _ := models.GetConfig("enable_daily_checkin")
	if enabled != "true" {
		return false
	}
	var done int
	models.DB.QueryRow("SELECT COUNT(*) FROM checkin_logs WHERE user_id=? AND date=?", userID, time.Now().Format("2006-01-02")).Scan(&done)
	return done == 0
}

// expectedCheckin describes the current checkin reward based on live config.
func expectedCheckin() string {
	mode, _ := models.GetConfig("checkin_mode")
	if mode == "random" {
		mn := atoiDefault(models.GetConfigOr("checkin_random_min", "1"), 1)
		mx := atoiDefault(models.GetConfigOr("checkin_random_max", "20"), 20)
		if mx < mn {
			mx = mn
		}
		return fmt.Sprintf("随机 %d ~ %d 积分", mn, mx)
	}
	n := atoiDefault(models.GetConfigOr("checkin_fixed_points", "10"), 10)
	return fmt.Sprintf("固定 %d 积分", n)
}

// renderError renders the branded error page (404/403 etc.) for any
// visitor, kept consistent whether they are logged in or not.
func renderError(w http.ResponseWriter, r *http.Request, code, message string) {
	noStore(w)
	uid, username, role := currentUser(r)
	data := map[string]interface{}{
		"Title":        message,
		"ErrorCode":    code,
		"ErrorMessage": message,
		"IsAdmin":      role == "admin",
		"IsLoggedIn":   uid > 0,
		"Points":       userPoints(uid),
		"Username":     username,
		"SiteName":     siteName(),
		"Toast":        consumeFlash(w, r),
		"Content":      "content-404",
	}
	if err := tpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func render404(w http.ResponseWriter, r *http.Request) {
	renderError(w, r, "404", "你访问的页面不存在或已被移除")
}

// rulesHandler renders the points & usage rules, pulling live values from
// settings so the page always matches the current configuration.
func rulesHandler(w http.ResponseWriter, r *http.Request) {
	mode, _ := models.GetConfig("checkin_mode")
	if mode == "" {
		mode = "fixed"
	}
	mn, mx := normalizeCheckinRange(
		models.GetConfigOr("checkin_random_min", "1"),
		models.GetConfigOr("checkin_random_max", "20"))
	renderPublicPage(w, r, "积分规则", "content-rules", map[string]interface{}{
		"GenCost":  models.GetConfigOr("generation_cost_points", "10"),
		"InitP":    models.GetConfigOr("initial_points", "0"),
		"Mode":     mode,
		"CheckinF": models.GetConfigOr("checkin_fixed_points", "10"),
		"CheckinM": mn,
		"CheckinX": mx,
	})
}

// normalizeCheckinRange clamps a random checkin range the same way the actual
// payout does: invalid values fall back to defaults and max < min is raised
// to min. All surfaces (rule page, expected-reward hint, payout) stay aligned.
func normalizeCheckinRange(minStr, maxStr string) (string, string) {
	mn, err1 := strconv.Atoi(minStr)
	mx, err2 := strconv.Atoi(maxStr)
	if err1 != nil || mn < 1 {
		mn = 1
	}
	if err2 != nil || mx < 1 {
		mx = 20
	}
	if mx < mn {
		mx = mn
	}
	return strconv.Itoa(mn), strconv.Itoa(mx)
}

// oauthEnabled reports whether Linux.do login is fully usable: the switch is
// on AND the OAuth client ID is configured. The login entry is hidden
// otherwise. Redirect URI 不要求必填：未配置时会自动使用当前站点的默认回调
// 地址（见 linuxdoCallbackURL），管理后台也会提示应填写的 Callback URL。
func oauthEnabled() bool {
	on, _ := models.GetConfig("enable_thirdparty_login")
	if on != "true" {
		return false
	}
	clientID, _ := models.GetConfig("linuxdo_client_id")
	return strings.TrimSpace(clientID) != ""
}

// unreadNotices reports whether the user has unread (newer) announcements:
// true when at least one active notice is newer than the user's last-read id.
// The nav bar then shows a red dot on the 公告 entry.
func unreadNotices(userID int64) bool {
	if userID <= 0 {
		return false
	}
	var latest int64
	if models.DB.QueryRow("SELECT MAX(id) FROM notices WHERE is_active=1").Scan(&latest) != nil || latest == 0 {
		return false
	}
	var read int64
	if models.DB.QueryRow("SELECT last_read_notice_id FROM users WHERE id=?", userID).Scan(&read) != nil {
		return false
	}
	return latest > read
}

// markNoticesRead advances the user's read position to the latest active
// notice, clearing the nav red dot. Called when the user views /notices.
func markNoticesRead(userID int64) {
	if userID <= 0 {
		return
	}
	var latest int64
	if models.DB.QueryRow("SELECT MAX(id) FROM notices WHERE is_active=1").Scan(&latest) != nil || latest == 0 {
		return
	}
	models.DB.Exec("UPDATE users SET last_read_notice_id=? WHERE id=? AND last_read_notice_id<?", latest, userID, latest)
}

// noticesHandler 展示全部启用公告（含历史），用户可查看公告列表。
// 登录用户访问本页即视为已读全部公告，导航“公告”红点随之消失。
func noticesHandler(w http.ResponseWriter, r *http.Request) {
	uid, _, _ := currentUser(r)
	if uid > 0 {
		markNoticesRead(uid)
	}
	rows, err := models.DB.Query("SELECT id, title, content, created_at FROM notices WHERE is_active=1 ORDER BY id DESC")
	if err != nil {
		renderError(w, r, "500", "公告加载失败")
		return
	}
	defer rows.Close()
	var list []map[string]interface{}
	for rows.Next() {
		var id int64
		var title, content, createdAt string
		if rows.Scan(&id, &title, &content, &createdAt) == nil {
			list = append(list, map[string]interface{}{
				"ID":        id,
				"Title":     title,
				"Content":   content,
				"CreatedAt": localTime(createdAt),
			})
		}
	}
	renderPublicPage(w, r, "公告", "content-notices", map[string]interface{}{
		"Notices":      list,
		"NoticesEmpty": len(list) == 0,
	})
}

// adminNoticesHandler 公告管理页：列表（含停用）供管理员查看。
func adminNoticesHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := models.DB.Query("SELECT id, title, content, is_active, created_at FROM notices ORDER BY id DESC")
	if err != nil {
		http.Error(w, "查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var list []map[string]interface{}
	for rows.Next() {
		var id int64
		var title, content, createdAt string
		var active int
		if rows.Scan(&id, &title, &content, &active, &createdAt) == nil {
			list = append(list, map[string]interface{}{
				"ID":        id,
				"Title":     title,
				"Content":   content,
				"Active":    active == 1,
				"CreatedAt": localTime(createdAt),
			})
		}
	}
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":   "公告管理",
		"Content": "content-admin-notices",
		"Notices": list,
	})
}

// adminNoticeAddHandler 新增公告。
func adminNoticeAddHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/notices", http.StatusSeeOther)
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	content := strings.TrimSpace(r.FormValue("content"))
	if content == "" {
		flashRedirect(w, r, "/admin/notices", "公告内容不能为空")
		return
	}
	if utf8.RuneCountInString(title) > 200 {
		flashRedirect(w, r, "/admin/notices", "公告标题过长（最多 200 字）")
		return
	}
	if utf8.RuneCountInString(content) > 4000 {
		flashRedirect(w, r, "/admin/notices", "公告内容过长（最多 4000 字）")
		return
	}
	active := 1
	if r.FormValue("is_active") != "1" {
		active = 0
	}
	if _, err := models.DB.Exec("INSERT INTO notices(title, content, is_active, created_at) VALUES(?,?,?,datetime('now'))", title, content, active); err != nil {
		http.Error(w, "保存失败", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/admin/notices", "公告已发布")
}

// adminNoticeDeleteHandler 删除公告（含历史）。
func adminNoticeDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/notices", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	models.DB.Exec("DELETE FROM notices WHERE id=?", id)
	flashRedirect(w, r, "/admin/notices", "公告已删除")
}

// adminNoticeToggleHandler 启用/停用公告。
func adminNoticeToggleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/notices", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	models.DB.Exec("UPDATE notices SET is_active = CASE is_active WHEN 1 THEN 0 ELSE 1 END WHERE id=?", id)
	flashRedirect(w, r, "/admin/notices", "公告状态已更新")
}

// renderPublicPage renders a page that is safe to view while logged out
// (unlike renderPage, it must NOT force IsLoggedIn=true).
func renderPublicPage(w http.ResponseWriter, r *http.Request, title, content string, extra map[string]interface{}) {
	uid, username, role := currentUser(r)
	data := map[string]interface{}{
		"Title":      title,
		"IsAdmin":    role == "admin",
		"IsLoggedIn": uid > 0,
		"Points":     int(userPoints(uid)),
		"Username":   username,
		"SiteName":   siteName(),
		"CSRF":       csrfToken(w, r),
		"Content":    content,
	}
	for k, v := range extra {
		data[k] = v
	}
	data["CheckinAvailable"] = uid > 0 && checkinAvailable(uid)
	data["UnreadNotices"] = unreadNotices(uid)
	data["Toast"] = consumeFlash(w, r)
	noStore(w)
	if err := tpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// leaderboardHandler shows the top creators by total creations, excluding
// admin accounts. Points are intentionally not shown — only today's count
// and the all-time count. Computed live so a disqualified (disabled) account
// drops off immediately.
func leaderboardHandler(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		Rank  int
		Name  string
		Today int
		Total int
	}
	// date(created_at,'localtime') 与 date('now','localtime') 均基于服务器本地时区，
	// 与签到等统计口径保持一致；仅统计成功任务（status='success'）。
	rows, err := models.DB.Query(`SELECT u.username,
		COUNT(g.id) AS total,
		COALESCE(SUM(CASE WHEN g.status='success' AND date(g.created_at,'localtime') = date('now','localtime') THEN 1 ELSE 0 END), 0) AS today
		FROM users u
		LEFT JOIN generation_records g ON g.user_id = u.id AND g.status = 'success'
		WHERE u.status = 1 AND u.role != 'admin'
		GROUP BY u.id ORDER BY total DESC, u.id ASC LIMIT 20`)
	if err != nil {
		http.Error(w, "查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	list := []map[string]interface{}{}
	rank := 0
	for rows.Next() {
		var e entry
		if rows.Scan(&e.Name, &e.Total, &e.Today) == nil {
			rank++
			e.Rank = rank
			list = append(list, map[string]interface{}{
				"Rank":  e.Rank,
				"Name":  e.Name,
				"Today": e.Today,
				"Total": e.Total,
			})
		}
	}
	// 登录用户可看到自己的实时名次（仅普通用户参与排行，管理员不计入）
	var me map[string]interface{}
	if uid, uname, role := currentUser(r); uid > 0 && role != "admin" {
		var myTotal, myToday int
		models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE user_id=? AND status='success'", uid).Scan(&myTotal)
		models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE user_id=? AND status='success' AND date(created_at,'localtime') = date('now','localtime')", uid).Scan(&myToday)
		var ahead int
		models.DB.QueryRow(`SELECT COUNT(*) FROM users u
			WHERE u.status = 1 AND u.role != 'admin' AND
			(SELECT COUNT(*) FROM generation_records g WHERE g.user_id = u.id AND g.status = 'success') > ?`, myTotal).Scan(&ahead)
		me = map[string]interface{}{"Name": uname, "Rank": ahead + 1, "Today": myToday, "Total": myTotal}
	}
	renderPublicPage(w, r, "创作排行榜", "content-leaderboard", map[string]interface{}{
		"Rankings": list,
		"Top":      len(list) > 0,
		"Me":       me,
	})
}

// isSafeLocalPath reports whether p is a same-origin local path usable as a
// post-login redirect target (blocks open-redirect via //host tricks).
func isSafeLocalPath(p string) bool {
	return p != "" && strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\\\r\n")
}

// setFlash stores a one-shot toast message in the session; it is consumed
// by the next rendered page and never appears in the URL.
func setFlash(w http.ResponseWriter, r *http.Request, msg string) {
	if msg == "" {
		return
	}
	s, _ := store.Get(r, "session")
	s.Values["flash_toast"] = msg
	s.Save(r, w)
}

// consumeFlash returns and clears the one-shot toast message, if any.
func consumeFlash(w http.ResponseWriter, r *http.Request) string {
	s, _ := store.Get(r, "session")
	if v, ok := s.Values["flash_toast"].(string); ok && v != "" {
		delete(s.Values, "flash_toast")
		s.Save(r, w)
		return v
	}
	return ""
}

// flashRedirect redirects to path with a one-shot toast message stored in
// the session (the URL itself stays clean).
func flashRedirect(w http.ResponseWriter, r *http.Request, path, msg string) {
	setFlash(w, r, msg)
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// isLoggedIn reports whether the current session has a valid user.
func isLoggedIn(r *http.Request) bool {
	session, _ := store.Get(r, "session")
	uid, ok := session.Values["userID"].(int64)
	return ok && uid > 0
}

// rotateSession expires the current session cookie and returns a fresh
// session with a newly generated ID, preventing session-fixation attacks.
// Call it once credentials have been verified, before storing user state.
func rotateSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	old, _ := store.Get(r, "session")
	old.Options.MaxAge = -1
	if err := old.Save(r, w); err != nil {
		log.Println("session rotation:", err)
	}
	s, _ := store.New(r, "session")
	return s
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if isLoggedIn(r) {
		http.Redirect(w, r, "/create", http.StatusSeeOther)
		return
	}
	next := ""
	if isSafeLocalPath(r.URL.Query().Get("next")) {
		next = r.URL.Query().Get("next")
	}
	if r.Method == http.MethodPost {
		if !verifyCSRF(r) {
			renderError(w, r, "400", "表单已过期，请刷新页面后重试")
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		key := clientIP(r)
		if isLoginLocked(key) {
			renderLogin(w, r, fmt.Sprintf("登录失败次数过多，请 %d 分钟后再试", int(loginLockWindow.Minutes())), next, username)
			return
		}
		if n := r.FormValue("next"); isSafeLocalPath(n) {
			next = n
		}
		password := r.FormValue("password")
		var user models.User
		err := models.DB.QueryRow("SELECT id, username, password_hash, role, status FROM users WHERE username=?", username).
			Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.Status)
		if err != nil || user.Status != 1 || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
			recordLoginFail(key)
			systemLog(r, 0, username, "login_fail", "用户名或密码错误", 0)
			renderLogin(w, r, "用户名或密码错误", next, username)
			return
		}
		clearLoginFails(key)
		systemLog(r, user.ID, user.Username, "login", "登录成功", 0)
		// 登录成功后重置会话，防止会话固定攻击
		session := rotateSession(w, r)
		session.Values["userID"] = user.ID
		session.Values["username"] = user.Username
		session.Values["role"] = user.Role
		session.Save(r, w)
		if next == "" {
			next = "/create"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	renderLogin(w, r, "", next, "")
}

func renderLogin(w http.ResponseWriter, r *http.Request, errMsg, next, lastUser string) {
	noStore(w)
	err := tpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
		"Title":        "登录",
		"Error":        errMsg,
		"IsAdmin":      false,
		"IsLoggedIn":   false,
		"Points":       0,
		"LastUsername": lastUser,
		"SiteName":     siteName(),
		"OAuthEnabled": oauthEnabled(),
		"Next":         next,
		"CSRF":         csrfToken(w, r),
		"Toast":        consumeFlash(w, r),
		"Content":      "content-login",
	})
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if isLoggedIn(r) {
		http.Redirect(w, r, "/create", http.StatusSeeOther)
		return
	}
	next := ""
	if isSafeLocalPath(r.URL.Query().Get("next")) {
		next = r.URL.Query().Get("next")
	}
	openReg, _ := models.GetConfig("open_registration")
	if openReg != "true" {
		renderError(w, r, "403", "注册功能已关闭，请联系管理员开通")
		return
	}
	pwReg, _ := models.GetConfig("enable_password_registration")
	if pwReg != "true" {
		renderRegister(w, r, "用户名密码注册已关闭，请通过第三方账号登录", "", next, "")
		return
	}
	if r.Method == http.MethodPost {
		// 异步提交：前端 fetch 拦截提交，出错由 JSON 原地展示，不刷新页面；
		// 普通提交（无 JS 环境/外部调用）保持原有整页渲染。
		if !verifyCSRF(r) {
			if ajaxRequest(r) {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "form": "表单已过期，请刷新页面后重试"})
				return
			}
			renderError(w, r, "400", "表单已过期，请刷新页面后重试")
			return
		}
		if n := r.FormValue("next"); isSafeLocalPath(n) {
			next = n
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		regCode := strings.ToUpper(strings.TrimSpace(r.FormValue("reg_code")))
		if len(username) < 2 || len(username) > 32 {
			formFail(w, r, renderRegister, "用户名长度需在 2-32 个字符之间", "", next, username)
			return
		}
		if len(password) < 6 {
			formFail(w, r, renderRegister, "密码长度至少 6 位", "", next, username)
			return
		}
		if r.FormValue("confirm_password") != password {
			formFail(w, r, renderRegister, "两次输入的密码不一致", "", next, username)
			return
		}
		requireCode, _ := models.GetConfig("require_reg_code")
		if requireCode == "true" && regCode == "" {
			formFail(w, r, renderRegister, "", "请输入注册码", next, username)
			return
		}
		hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		initialPoints := atoiDefault(models.GetConfigOr("initial_points", "0"), 0)

		if requireCode == "true" {
			// 原子占用注册码：注册码的“占码”与账号创建同在事务内，
			// 并靠 RowsAffected 校验唯一占用，杜绝同一码并发注册多个账号
			tx, err := models.DB.Begin()
			if err != nil {
				if ajaxRequest(r) {
					writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "form": "系统繁忙，请重试"})
					return
				}
				http.Error(w, "系统繁忙，请重试", http.StatusInternalServerError)
				return
			}
			res, err := tx.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)",
				username, string(hashed), initialPoints, "user", 1)
			if err != nil {
				tx.Rollback()
				formFail(w, r, renderRegister, "用户名已存在或输入有误", "", next, username)
				return
			}
			uid, _ := res.LastInsertId()
			res2, err := tx.Exec("UPDATE redeem_codes SET status='used', used_by=?, used_at=CURRENT_TIMESTAMP WHERE code=? AND status='active' AND (kind='' OR kind='register')", uid, regCode)
			if err != nil {
				tx.Rollback()
				if ajaxRequest(r) {
					writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "form": "系统繁忙，请重试"})
					return
				}
				http.Error(w, "系统繁忙，请重试", http.StatusInternalServerError)
				return
			}
			if n, _ := res2.RowsAffected(); n == 0 {
				// 注册码已被他人占用：回滚账号创建，不产生垃圾用户
				tx.Rollback()
				formFail(w, r, renderRegister, "", "注册码无效或已被使用", next, username)
				return
			}
			if err := tx.Commit(); err != nil {
				if ajaxRequest(r) {
					writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "form": "系统繁忙，请重试"})
					return
				}
				http.Error(w, "系统繁忙，请重试", http.StatusInternalServerError)
				return
			}
			if initialPoints > 0 {
				logPoints(uid, int64(initialPoints), "注册赠送")
			}
			systemLog(r, uid, username, "register", "注册成功（凭注册码）", int64(initialPoints))
			if next == "" {
				next = "/login"
			} else {
				next = "/login?next=" + url.QueryEscape(next)
			}
			registerAJAXSuccess(w, r, next)
			return
		}

		_, err := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)",
			username, string(hashed), initialPoints, "user", 1)
		if err != nil {
			formFail(w, r, renderRegister, "用户名已存在或输入有误", "", next, username)
			return
		}
		var uid int64
		models.DB.QueryRow("SELECT id FROM users WHERE username=?", username).Scan(&uid)
		if initialPoints > 0 {
			logPoints(uid, int64(initialPoints), "注册赠送")
		}
		systemLog(r, uid, username, "register", "注册成功", int64(initialPoints))
		if next == "" {
			next = "/login"
		} else {
			next = "/login?next=" + url.QueryEscape(next)
		}
		registerAJAXSuccess(w, r, next)
		return
	}
	renderRegister(w, r, "", "", next, "")
}

// registerAJAXSuccess 是注册成功后的统一出口：异步请求返回 JSON（前端跳转
// redirect，flash 消息随会话 cookie 生效），普通请求维持原有 flash 重定向。
func registerAJAXSuccess(w http.ResponseWriter, r *http.Request, next string) {
	if ajaxRequest(r) {
		setFlash(w, r, "注册成功，请登录")
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "redirect": next})
		return
	}
	flashRedirect(w, r, next, "注册成功，请登录")
}

// renderRegister 渲染注册页：errMsg（用户名/密码等）显示在表单顶部，
// regCodeErr（注册码问题）以红色文字显示在注册码输入框下方；出错时重渲染
// 注册页本身，不跳转到其它页面。
func renderRegister(w http.ResponseWriter, r *http.Request, errMsg, regCodeErr, next, lastUser string) {
	noStore(w)
	reqCode, _ := models.GetConfig("require_reg_code")
	err := tpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
		"Title":          "注册",
		"Error":          errMsg,
		"RegCodeError":   regCodeErr,
		"IsAdmin":        false,
		"IsLoggedIn":     false,
		"Points":         0,
		"RequireRegCode": reqCode == "true",
		"LastUsername":   lastUser,
		"SiteName":       siteName(),
		"Next":           next,
		"CSRF":           csrfToken(w, r),
		"Toast":          consumeFlash(w, r),
		"Content":        "content-register",
	})
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session, _ := store.Get(r, "session")
	uid, _ := session.Values["userID"].(int64)
	uname, _ := session.Values["username"].(string)
	session.Values["userID"] = nil
	session.Values["username"] = nil
	session.Values["role"] = nil
	session.Save(r, w)
	if uid > 0 {
		systemLog(r, uid, uname, "logout", "退出登录", 0)
	}
	flashRedirect(w, r, "/login", "已退出登录")
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		userID, ok := session.Values["userID"].(int64)
		if !ok || userID == 0 {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		var username string
		var status int
		err := models.DB.QueryRow("SELECT username, status FROM users WHERE id=?", userID).Scan(&username, &status)
		if err != nil || status != 1 {
			// 用户不存在或已被禁用：清理会话
			session.Values["userID"] = nil
			session.Values["username"] = nil
			session.Values["role"] = nil
			session.Save(r, w)
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		// 会话中的用户名与数据库保持同步
		if u, ok := session.Values["username"].(string); !ok || u != username {
			session.Values["username"] = username
			session.Save(r, w)
		}
		next(w, r)
	}
}

func adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		role, ok := session.Values["role"].(string)
		if !ok || role != "admin" {
			renderError(w, r, "403", "需要管理员权限")
			return
		}
		// 与数据库中的角色保持一致，防止被降级后仍可访问后台
		uid, _ := session.Values["userID"].(int64)
		var dbRole string
		if err := models.DB.QueryRow("SELECT role FROM users WHERE id=?", uid).Scan(&dbRole); err != nil || dbRole != "admin" {
			renderError(w, r, "403", "需要管理员权限")
			return
		}
		next(w, r)
	}
}

func currentUser(r *http.Request) (int64, string, string) {
	session, _ := store.Get(r, "session")
	uid, _ := session.Values["userID"].(int64)
	username, _ := session.Values["username"].(string)
	role, _ := session.Values["role"].(string)
	return uid, username, role
}

func userPoints(uid int64) int64 {
	var p int64
	models.DB.QueryRow("SELECT points FROM users WHERE id=?", uid).Scan(&p)
	return p
}

// logPoints records a points change together with the new balance.
func logPoints(uid, delta int64, desc string) {
	var balance int64
	models.DB.QueryRow("SELECT points FROM users WHERE id=?", uid).Scan(&balance)
	models.DB.Exec("INSERT INTO points_log(user_id, delta, balance, description) VALUES(?,?,?,?)", uid, delta, balance, desc)
}

// systemLogActions 行为的中文名（管理后台日志筛选下拉与列表展示共用）。
var systemLogActions = map[string]string{
	"login":        "登录",
	"login_fail":   "登录失败",
	"logout":       "退出登录",
	"register":     "注册",
	"checkin":      "签到",
	"create":       "创作",
	"redeem":       "兑换",
	"api":          "API 调用",
	"admin_rename": "管理员操作",
}

// systemLogActionLabel 返回行为的中文名，未知行为原样返回。
func systemLogActionLabel(action string) string {
	if v, ok := systemLogActions[action]; ok {
		return v
	}
	return action
}

// systemLog 写入一条系统日志（用户行为审计）：时间、用户名、行为、详情、积分
// 变动、IP 均记录，管理后台 /admin/logs 支持逐项筛选。r 可为 nil（无请求时）。
func systemLog(r *http.Request, userID int64, username, action, detail string, pointsDelta int64) {
	ip := ""
	if r != nil {
		ip = clientIP(r)
	}
	models.DB.Exec("INSERT INTO system_logs(user_id, username, action, detail, points_delta, ip) VALUES(?,?,?,?,?,?)",
		userID, username, action, detail, pointsDelta, ip)
}

// profileHandler renders a personal account overview: balances, statistics,
// recent creations and recent points activity.
func profileHandler(w http.ResponseWriter, r *http.Request) {
	uid, _, _ := currentUser(r)
	var role, createdAt string
	var status int
	models.DB.QueryRow("SELECT role, created_at, status FROM users WHERE id=?", uid).Scan(&role, &createdAt, &status)

	var got, spent int64
	models.DB.QueryRow("SELECT COALESCE(SUM(CASE WHEN delta>0 THEN delta ELSE 0 END),0), COALESCE(SUM(CASE WHEN delta<0 THEN -delta ELSE 0 END),0) FROM points_log WHERE user_id=?", uid).Scan(&got, &spent)
	var checkinTotal, recordTotal int64
	models.DB.QueryRow("SELECT COUNT(*) FROM checkin_logs WHERE user_id=?", uid).Scan(&checkinTotal)
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE user_id=? AND status='success'", uid).Scan(&recordTotal)
	var lastSign string
	models.DB.QueryRow("SELECT MAX(date) FROM checkin_logs WHERE user_id=?", uid).Scan(&lastSign)

	var recentRecords []map[string]interface{}
	rows, err := models.DB.Query("SELECT prompt, cost_points, created_at FROM generation_records WHERE user_id=? AND status='success' ORDER BY id DESC LIMIT 8", uid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var prompt, t string
			var cost int
			if rows.Scan(&prompt, &cost, &t) == nil {
				recentRecords = append(recentRecords, map[string]interface{}{
					"Prompt":    truncateRunes(prompt, 32),
					"Cost":      cost,
					"CreatedAt": localTime(t),
				})
			}
		}
	}
	var recentPoints []map[string]interface{}
	rows2, err := models.DB.Query(`SELECT delta, balance, description, created_at
		FROM points_log WHERE user_id=? ORDER BY id DESC LIMIT 8`, uid)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var delta, balance int64
			var desc, t string
			if rows2.Scan(&delta, &balance, &desc, &t) == nil {
				recentPoints = append(recentPoints, map[string]interface{}{
					"Delta":     delta,
					"Balance":   balance,
					"Desc":      desc,
					"CreatedAt": localTime(t),
				})
			}
		}
	}

	// 用户 API Key：数据库只存哈希，页面展示掩码；新生成的明文通过
	// session flash 传递一次，渲染后即清除
	apiKeyHash := models.GetAPIKeyHash(uid)
	hasKey := apiKeyHash != ""
	mask := ""
	if len(apiKeyHash) >= 8 {
		mask = apiKeyHash[:8] + "****"
	} else if hasKey {
		mask = "****"
	}
	var newKey string
	if sess, _ := store.Get(r, "session"); sess != nil {
		if v, ok := sess.Values["new_api_key"].(string); ok && v != "" {
			newKey = v
			delete(sess.Values, "new_api_key")
			sess.Save(r, w)
		}
	}

	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":        "个人主页",
		"JoinedAt":     localTime(createdAt),
		"Role":         role,
		"Status":       status,
		"TotalGot":     got,
		"TotalUsed":    spent,
		"CheckinCount": checkinTotal,
		"RecordCount":  recordTotal,
		"LastSign":     lastSign,
		"RecentRecs":   recentRecords,
		"RecentPts":    recentPoints,
		"HasAPIKey":    hasKey,
		"ApiKeyMask":   mask,
		"NewAPIKey":    newKey,
		"OAuthEnabled": oauthEnabled(),
		"OAuthProvider": func() string {
			var p string
			models.DB.QueryRow("SELECT COALESCE(oauth_provider,'') FROM users WHERE id=?", uid).Scan(&p)
			return p
		}(),
		"Content": "content-profile",
	})
}

func renderPage(w http.ResponseWriter, r *http.Request, templateName string, data map[string]interface{}) {
	noStore(w)
	uid, username, role := currentUser(r)
	if data == nil {
		data = make(map[string]interface{})
	}
	data["IsLoggedIn"] = true
	// 以数据库中的最新角色为准，保证被降级/提升的管理员导航立即生效
	if uid > 0 {
		var dbRole string
		if err := models.DB.QueryRow("SELECT role FROM users WHERE id=?", uid).Scan(&dbRole); err == nil {
			role = dbRole
		}
	}
	data["IsAdmin"] = role == "admin"
	data["Points"] = int(userPoints(uid))
	data["Username"] = username
	data["SiteName"] = siteName()
	data["CSRF"] = csrfToken(w, r)
	// 导航角标：今天还未签到且签到功能开启时给“每日签到”加提示点
	data["CheckinAvailable"] = uid > 0 && checkinAvailable(uid)
	data["UnreadNotices"] = unreadNotices(uid)
	data["Toast"] = consumeFlash(w, r)
	err := tpl.ExecuteTemplate(w, templateName, data)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// createPage assembles the creation page (form + recent tasks + optional
// active task card), shared by GET /create and the POST /generate error
// branches so every render carries the same channel list and task list.
func createPage(w http.ResponseWriter, r *http.Request, extra map[string]interface{}) {
	data := map[string]interface{}{
		"Title":        "创意生成",
		"Cost":         generationCost(),
		"DefaultModel": models.GetConfigOr("generation_model", "grok-imagine-image-lite"),
		"GenToken":     mintToken(w, r, "gen_token"),
		"Result":       nil,
		"Error":        "",
		"Content":      "content-create",
	}
	// 回填上次使用的创作参数（会话内持久，跨访问保持）
	if sess, err := store.Get(r, "session"); err == nil {
		if v, ok := sess.Values["lastChannel"].(string); ok && v != "" {
			data["LastChannel"] = v
		}
		if v, ok := sess.Values["lastRatio"].(string); ok && v != "" {
			data["LastRatio"] = v
		}
		if v, ok := sess.Values["lastResolution"].(string); ok && v != "" {
			data["LastResolution"] = v
		}
		if v, ok := sess.Values["lastN"].(string); ok && v != "" {
			data["LastN"] = v
		}
		if v, ok := sess.Values["lastModel"].(string); ok && v != "" {
			data["LastModel"] = v
		}
	}
	// 从 /records 点「再生成」带过来的提示词，直接回填到表单
	if p := strings.TrimSpace(r.URL.Query().Get("prompt")); p != "" {
		if utf8.RuneCountInString(p) > 4000 {
			p = string([]rune(p)[:4000])
		}
		data["LastPrompt"] = p
	}
	uid, _, _ := currentUser(r)
	// 异步任务：?task=<id> 表示刚提交的任务，展示进度卡并交给前端轮询
	if t := strings.TrimSpace(r.URL.Query().Get("task")); t != "" {
		if id, err := strconv.ParseInt(t, 10, 64); err == nil && id > 0 {
			var st string
			if err := models.DB.QueryRow("SELECT status FROM generation_records WHERE id=? AND user_id=?", id, uid).Scan(&st); err == nil {
				data["TaskID"] = id
				if st == "pending" {
					st = "processing"
				}
				data["TaskStatus"] = st
			}
		}
	}
	// 渠道下拉：展示全部渠道（"编号 · 渠道名"，NSFW 渠道带标注）；
	// 默认选中第一个渠道，上次选择（会话内记录的是渠道稳定编号）仍有效时沿用
	defIdx := -1
	lastChannel, _ := data["LastChannel"].(string)
	eps := loadEndpoints()
	if id, err := strconv.Atoi(lastChannel); err == nil {
		for i, ep := range eps {
			if ep.ID == id {
				defIdx = i
				break
			}
		}
	}
	if defIdx < 0 && len(eps) > 0 {
		defIdx = 0
	}
	data["Channels"] = allChannels()
	data["DefChannelIdx"] = defIdx
	// 默认渠道的分辨率档位：上次选择在档位内则沿用，否则取档位第一个
	defResolution := ""
	if defIdx >= 0 && defIdx < len(eps) {
		last := ""
		if v, ok := data["LastResolution"].(string); ok {
			last = v
		}
		for _, r := range eps[defIdx].Resolutions {
			if r == last {
				defResolution = r
				break
			}
		}
		if defResolution == "" && len(eps[defIdx].Resolutions) > 0 {
			defResolution = eps[defIdx].Resolutions[0]
		}
	}
	data["DefResolution"] = defResolution
	// 默认渠道的模型：上次选择（会话内）在渠道可用模型内则沿用，否则取第一个
	defModel := ""
	if defIdx >= 0 && defIdx < len(eps) {
		last := ""
		if v, ok := data["LastModel"].(string); ok {
			last = v
		}
		for _, m := range eps[defIdx].Models {
			if m == last {
				defModel = m
				break
			}
		}
		if defModel == "" && len(eps[defIdx].Models) > 0 {
			defModel = eps[defIdx].Models[0]
		}
	}
	data["DefModel"] = defModel
	data["RecentTasks"] = recentTasks(uid, 3)
	for k, v := range extra {
		data[k] = v
	}
	renderPage(w, r, "layout.html", data)
}

func createHandler(w http.ResponseWriter, r *http.Request) {
	createPage(w, r, nil)
}

func generationCost() int {
	return atoiDefault(models.GetConfigOr("generation_cost_points", "10"), 10)
}

func siteName() string {
	return models.GetConfigOr("site_name", "在线创作平台")
}

// generateHandler 不再同步等待上游出图：校验通过后先扣分、落一条
// processing 记录并入队，由后台 worker 异步生成；页面跳转到
// /create?task=<id> 由前端轮询 /generate/status 同步状态。
// 提交后立即 303 跳转（历史栈中只有 GET），浏览器后退不会再触发
// “确认重新提交表单”的报错。
func generateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/create", http.StatusSeeOther)
		return
	}
	if !verifyCSRF(r) {
		renderError(w, r, "400", "表单已过期，请刷新页面后重试")
		return
	}
	// 一次性令牌：刷新/重复提交不会再次扣分
	if !consumeToken(w, r, "gen_token") {
		flashRedirect(w, r, "/create", "请勿重复提交，本次未扣分")
		return
	}
	userID, username, _ := currentUser(r)
	baseCost := generationCost()

	// 提前读取表单值，便于回显给用户
	lastPrompt := strings.TrimSpace(r.FormValue("prompt"))
	lastChannel := strings.TrimSpace(r.FormValue("channel"))
	lastRatio := r.FormValue("aspect_ratio")
	lastResolution := r.FormValue("resolution")
	lastN := r.FormValue("n")
	lastModel := strings.TrimSpace(r.FormValue("model"))
	// 返回格式由系统后台自适应固定为 URL（生成图片本地落盘，统一以
	// 图片路径提供），创作界面不再提供 url/b64_json 选择。
	lastFormat := "url"
	// 记住用户最近一次使用的参数，下次进入创建页自动回填
	if sess, err := store.Get(r, "session"); err == nil {
		sess.Values["lastChannel"] = lastChannel
		sess.Values["lastRatio"] = lastRatio
		sess.Values["lastResolution"] = lastResolution
		sess.Values["lastN"] = lastN
		sess.Values["lastModel"] = lastModel
		sess.Save(r, w)
	}
	n := atoiDefault(lastN, 1)
	if n < 1 {
		n = 1
	}
	if n > 4 {
		n = 4
	}
	// 以规范化后的张数覆盖会话值，避免下次进入创建页时 select 无对应选项
	lastN = strconv.Itoa(n)
	// 按生成数量累计扣费
	cost := baseCost * n
	points := userPoints(userID)

	if lastPrompt == "" {
		createPage(w, r, map[string]interface{}{
			"Error": "请输入提示词",
			"LastN": lastN,
		})
		return
	}

	if utf8.RuneCountInString(lastPrompt) > 4000 {
		createPage(w, r, map[string]interface{}{
			"Error":          "提示词过长，最多 4000 字",
			"LastPrompt":     lastPrompt,
			"LastChannel":    lastChannel,
			"LastRatio":      lastRatio,
			"LastResolution": lastResolution,
			"LastN":          lastN,
		})
		return
	}

	if points < int64(cost) {
		createPage(w, r, map[string]interface{}{
			"Error":          fmt.Sprintf("积分不足（本次需要 %d 积分），请先签到或兑换积分", cost),
			"LastPrompt":     lastPrompt,
			"LastChannel":    lastChannel,
			"LastRatio":      lastRatio,
			"LastResolution": lastResolution,
			"LastN":          lastN,
		})
		return
	}

	// 解析所选渠道：NSFW 属性由渠道自身决定，直接作为记录的 nsfw 标志
	selectedEp, err := resolveChannel(lastChannel)
	if err != nil {
		createPage(w, r, map[string]interface{}{
			"Error":          err.Error(),
			"LastPrompt":     lastPrompt,
			"LastChannel":    lastChannel,
			"LastRatio":      lastRatio,
			"LastResolution": lastResolution,
			"LastN":          lastN,
		})
		return
	}
	nsfwFlag := 0
	if selectedEp.NSFW {
		nsfwFlag = 1
	}

	// 所选渠道的分辨率档位校验：只允许提交渠道支持的档位
	if !containsString(selectedEp.Resolutions, lastResolution) {
		createPage(w, r, map[string]interface{}{
			"Error":          fmt.Sprintf("所选渠道不支持 %s 分辨率，请选择渠道支持的分辨率档位", lastResolution),
			"LastPrompt":     lastPrompt,
			"LastChannel":    lastChannel,
			"LastRatio":      lastRatio,
			"LastResolution": lastResolution,
			"LastN":          lastN,
		})
		return
	}

	// 所选渠道的模型校验：创作界面只提供渠道可用模型，提交其它模型时拦截
	if lastModel != "" && !containsString(selectedEp.Models, lastModel) {
		createPage(w, r, map[string]interface{}{
			"Error":          fmt.Sprintf("所选渠道不支持模型 %s，请选择渠道支持的模型", lastModel),
			"LastPrompt":     lastPrompt,
			"LastChannel":    lastChannel,
			"LastRatio":      lastRatio,
			"LastResolution": lastResolution,
			"LastN":          lastN,
		})
		return
	}

	// 条件扣减：只有余额足够才扣，从根上杜绝并发请求把积分扣成负数
	res, err := models.DB.Exec("UPDATE users SET points = points - ? WHERE id=? AND points >= ?", cost, userID, cost)
	if err != nil {
		http.Error(w, "系统繁忙，请重试", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		createPage(w, r, map[string]interface{}{
			"Error":          "积分不足（可能存在并发扣减），请补充积分后重试",
			"LastPrompt":     lastPrompt,
			"LastChannel":    lastChannel,
			"LastRatio":      lastRatio,
			"LastResolution": lastResolution,
			"LastN":          lastN,
		})
		return
	}

	// 优先使用用户在创作界面选择的模型；未选择时回退渠道默认模型
	chanModel := strings.TrimSpace(lastModel)
	if chanModel == "" {
		chanModel = strings.TrimSpace(selectedEp.Model)
	}
	if chanModel == "" {
		chanModel = models.GetConfigOr("generation_model", "grok-imagine-image-lite")
	}
	res, err = models.DB.Exec("INSERT INTO generation_records(user_id, prompt, model, n, aspect_ratio, resolution, response_format, cost_points, status, nsfw, channel) VALUES(?,?,?,?,?,?,?,?,'processing',?,?)",
		userID, lastPrompt, chanModel, n, lastRatio, lastResolution, lastFormat, cost, nsfwFlag, selectedEp.Name)
	if err != nil {
		// 扣款成功但记录落库失败：立即退回积分，避免"扣了分却没记录"
		models.DB.Exec("UPDATE users SET points = points + ? WHERE id=?", cost, userID)
		logPoints(userID, int64(cost), "生成任务创建失败，积分退回")
		createPage(w, r, map[string]interface{}{
			"Error":          "任务创建失败，积分已退回，请重试",
			"LastPrompt":     lastPrompt,
			"LastChannel":    lastChannel,
			"LastRatio":      lastRatio,
			"LastResolution": lastResolution,
			"LastN":          lastN,
		})
		return
	}
	rid, _ := res.LastInsertId()
	logPoints(userID, -int64(cost), "AI 图片创作消耗")
	systemLog(r, userID, username, "create", fmt.Sprintf("创作生成 %d 张（%s），任务 #%d", n, chanModel, rid), -int64(cost))

	// 入队：worker 异步生成，前端轮询 /generate/status 同步任务状态
	taskQueue <- genTask{recordID: rid}

	flashRedirect(w, r, fmt.Sprintf("/create?task=%d", rid), "生成任务已提交，正在后台生成，请稍候…")
}

// ------- 多接口渠道（普通 / NSFW） -------

// loadEndpoints 解析系统设置中的多渠道列表（generation_endpoints JSON 数组），
// 列表缺失或损坏时回退到旧的单接口配置（generation_api_url/key/model）。
// 地址为空的行会被丢弃；同时允许 API Key 为空（正常渠道留空时生成会失败，
// 由 worker 侧报错并退回积分，避免界面出现半配置状态）。
// 未填写渠道名称的行会自动命名为"渠道 N"，保证创作界面始终有可显示的渠道名。
func loadEndpoints() []GenerationEndpoint {
	raw, _ := models.GetConfig("generation_endpoints")
	if raw != "" {
		var eps []GenerationEndpoint
		if err := json.Unmarshal([]byte(raw), &eps); err == nil {
			valid := eps[:0]
			for _, ep := range eps {
				if strings.TrimSpace(ep.APIURL) != "" {
					valid = append(valid, ep)
				}
			}
			if len(valid) > 0 {
				for i := range valid {
					if strings.TrimSpace(valid[i].Name) == "" {
						valid[i].Name = fmt.Sprintf("渠道%d", i+1)
					}
					// 未配置分辨率档位时按默认 1k/2k 提供选项
					if len(valid[i].Resolutions) == 0 {
						valid[i].Resolutions = append([]string(nil), defaultResolutions...)
					}
					// 未配置可用模型时按默认快捷模型提供选项
					if len(valid[i].Models) == 0 {
						valid[i].Models = append([]string(nil), defaultModels...)
					}
				}
				// 稳定编号兜底：配置中缺失 id 的历史数据在内存中按顺序补发
				// （正式环境的持久化补发在启动时由 migrateEndpointIDs 完成；
				// 这里仅为保证任何入口读取到的渠道都有编号可用）。
				fillEndpointIDs(valid)
				return valid
			}
		}
	}
	apiURL, _ := models.GetConfig("generation_api_url")
	apiKey, _ := models.GetConfig("generation_api_key")
	if apiURL != "" && apiKey != "" {
		return []GenerationEndpoint{{
			ID:     1,
			Name:   "默认渠道",
			APIURL: apiURL,
			APIKey: apiKey,
			Model:  models.GetConfigOr("generation_model", "grok-imagine-image-lite"),
		}}
	}
	return nil
}

// fillEndpointIDs 为切片中缺失编号（ID<=0）的渠道补发稳定编号：
// 在已有最大编号基础上递增分配（1 开始，编号不复用）。
func fillEndpointIDs(eps []GenerationEndpoint) {
	maxID := 0
	for _, ep := range eps {
		if ep.ID > maxID {
			maxID = ep.ID
		}
	}
	for i := range eps {
		if eps[i].ID <= 0 {
			maxID++
			eps[i].ID = maxID
		}
	}
}

// migrateEndpointIDs 启动时执行一次：为历史配置中缺失编号的渠道
// 补发稳定编号并持久化，此后渠道编号不再随增删/调整顺序变化；
// 同时把编号计数器 endpoints_max_id 抬升到当前最大值（保证后续
// 新渠道分配到的编号不会与现有渠道冲突）。
func migrateEndpointIDs() {
	raw, _ := models.GetConfig("generation_endpoints")
	if raw == "" {
		return
	}
	var eps []GenerationEndpoint
	if err := json.Unmarshal([]byte(raw), &eps); err != nil {
		return
	}
	missing := 0
	for _, ep := range eps {
		if ep.ID <= 0 {
			missing++
		}
	}
	changed := false
	if missing > 0 {
		fillEndpointIDs(eps)
		changed = true
	}
	maxID := 0
	for _, ep := range eps {
		if ep.ID > maxID {
			maxID = ep.ID
		}
	}
	if counter := atoiDefault(models.GetConfigOr("endpoints_max_id", "0"), 0); maxID > counter {
		changed = true
	}
	if changed {
		if b, err := json.Marshal(eps); err == nil {
			models.SetConfig("generation_endpoints", string(b))
			models.SetConfig("endpoints_max_id", strconv.Itoa(maxID))
			if missing > 0 {
				log.Printf("endpoints: backfilled %d stable channel id(s)", missing)
			}
		}
	}
}

// selectEndpoint 选择本次请求使用的渠道：NSFW 请求必须走标记为 NSFW 的渠道，
// 普通请求走普通渠道；没有匹配渠道时报错（生成入口已预检，worker 侧兜底）。
func selectEndpoint(nsfw bool) (GenerationEndpoint, error) {
	eps := loadEndpoints()
	for _, ep := range eps {
		if ep.NSFW == nsfw {
			return ep, nil
		}
	}
	if nsfw {
		return GenerationEndpoint{}, errors.New("未配置 NSFW 渠道，请在系统设置中添加")
	}
	if len(eps) == 0 {
		return GenerationEndpoint{}, errors.New("图片生成服务未配置，请联系管理员")
	}
	return GenerationEndpoint{}, errors.New("未配置普通生成渠道，请在系统设置中添加")
}

// channelOption 是创作界面渠道下拉的一个选项。ID 为渠道稳定编号
// （表单提交值 / API channel 参数取值）；Idx 为列表中的位置（仅用于
// 模板比较默认选中项）。
type channelOption struct {
	ID             int
	Idx            int
	Name           string
	NSFW           bool
	NSFWStr        string // "1"/"0"，供模板生成 data-nsfw 标记
	Resolutions    []string
	ResolutionsCSV string // 逗号分隔，供模板生成 data-resolutions 标记
	Models         []string
	ModelsCSV      string // 逗号分隔，供模板生成 data-models 标记
}

// allChannels 返回创作界面可选的完整渠道列表（普通 + NSFW 都展示，
// NSFW 渠道在文案上标注），渠道名即系统设置里配置的名称。
func allChannels() []channelOption {
	opts := []channelOption{}
	for i, ep := range loadEndpoints() {
		name := ep.Name
		if ep.NSFW {
			name = name + "（NSFW）"
		}
		nsfwStr := "0"
		if ep.NSFW {
			nsfwStr = "1"
		}
		res := ep.Resolutions
		if len(res) == 0 {
			res = append([]string(nil), defaultResolutions...)
		}
		ms := ep.Models
		if len(ms) == 0 {
			ms = append([]string(nil), defaultModels...)
		}
		opts = append(opts, channelOption{
			ID: ep.ID, Idx: i, Name: name, NSFW: ep.NSFW, NSFWStr: nsfwStr,
			Resolutions: res, ResolutionsCSV: strings.Join(res, ","),
			Models: ms, ModelsCSV: strings.Join(ms, ","),
		})
	}
	return opts
}

// resolveChannel 按"渠道稳定编号"解析所选渠道：编号在渠道创建时分配并
// 持久化（见 GenerationEndpoint.ID），不随渠道增删/调整顺序变化（获取方式：
// 创作页渠道下拉的"编号 · 渠道名"，或 GET /api/v1/channels 的 id 字段）。
// 留空 = 自动选第一个普通渠道（与 API 文档约定一致）；没有普通渠道时
// 兜底取第一个。渠道是否为 NSFW 由渠道自身配置决定。
func resolveChannel(channelStr string) (GenerationEndpoint, error) {
	eps := loadEndpoints()
	if len(eps) == 0 {
		return GenerationEndpoint{}, errors.New("图片生成服务未配置，请联系管理员")
	}
	channelStr = strings.TrimSpace(channelStr)
	if channelStr == "" {
		for _, ep := range eps {
			if !ep.NSFW {
				return ep, nil
			}
		}
		return eps[0], nil // 全部为 NSFW 渠道时兜底取第一个
	}
	id, err := strconv.Atoi(channelStr)
	if err == nil {
		for _, ep := range eps {
			if ep.ID == id {
				return ep, nil
			}
		}
	}
	return GenerationEndpoint{}, errors.New("渠道编号无效：请在创作页渠道下拉中选择，或调用 GET /api/v1/channels 查询渠道编号")
}

// containsString 判断字符串切片中是否存在指定值。
func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// ------- 异步生成任务 -------

// recentTasks 返回用户最近的生成任务（任意状态），供创作页"最近任务"
// 区域与 /generate/status 轮询响应共用。
func recentTasks(userID int64, limit int) []map[string]interface{} {
	list := []map[string]interface{}{}
	rows, err := models.DB.Query(`SELECT id, prompt, n, status, image_url, error_msg, created_at
		FROM generation_records WHERE user_id=? ORDER BY id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return list
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var prompt string
		var n int
		var status, imageURL, errMsg, createdAt string
		if rows.Scan(&id, &prompt, &n, &status, &imageURL, &errMsg, &createdAt) == nil {
			list = append(list, map[string]interface{}{
				"ID":        id,
				"Prompt":    truncateRunes(prompt, 60),
				"N":         n,
				"Status":    status,
				"ImageURL":  imageURL,
				"ErrorMsg":  errMsg,
				"Images":    recordImagePaths(id),
				"CreatedAt": localTime(createdAt),
			})
		}
	}
	return list
}

// recordImagePaths lists every archived image path of a record.
func recordImagePaths(recordID int64) []string {
	var paths []string
	rows, err := models.DB.Query("SELECT path, storage_path FROM generation_images WHERE record_id=? ORDER BY idx", recordID)
	if err != nil {
		return paths
	}
	defer rows.Close()
	for rows.Next() {
		var p, sp string
		if rows.Scan(&p, &sp) == nil {
			if p != "" {
				paths = append(paths, p)
			} else if sp != "" {
				// 本地文件已清理但有外部存储备份：用备用地址，
				// 与 records / apiStatus 的回退行为保持一致。
				paths = append(paths, sp)
			}
		}
	}
	return paths
}

// generationWorker 消费异步任务队列，串行调上游生成，避免并发打满上游。
func generationWorker() {
	for t := range taskQueue {
		processGeneration(t.recordID)
	}
}

// recoverPendingTasks 把数据库中仍处于 processing 的任务重新入队，
// 保证服务重启后未完成的生成任务继续执行而不是永久卡死。
func recoverPendingTasks() {
	rows, err := models.DB.Query("SELECT id FROM generation_records WHERE status='processing' ORDER BY id ASC")
	if err != nil {
		log.Printf("recover pending tasks: %v", err)
		return
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			taskQueue <- genTask{recordID: id}
			n++
		}
	}
	if n > 0 {
		log.Printf("recovered %d pending generation task(s)", n)
	}
}

// processGeneration 真正执行一次图片生成：读取任务记录 → 选渠道 →
// 调 API → 落盘图片 → 更新记录；失败时标记 failed 并退回积分。
// 更新语句带 status='processing' 条件 + 记录待处理检查，天然幂等，
// worker panic 后 defer 重试不会重复退分。
func processGeneration(recordID int64) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("generation worker panic on record %d: %v", recordID, p)
			markTaskFailed(recordID, "服务内部错误，已退回积分，请重试")
		}
	}()
	var userID int64
	var prompt, model, ratio, res, format, status, channel string
	var n, nsfw int
	var cost int64
	err := models.DB.QueryRow(`SELECT user_id, prompt, model, n, aspect_ratio, resolution, response_format, cost_points, status, nsfw, channel
		FROM generation_records WHERE id=?`, recordID).
		Scan(&userID, &prompt, &model, &n, &ratio, &res, &format, &cost, &status, &nsfw, &channel)
	if err != nil {
		log.Printf("load task %d: %v", recordID, err)
		return
	}
	// 记录已不在待处理状态（被删除/已处理）则跳过
	if status != "processing" {
		return
	}
	// 优先使用提交时选中的渠道（按渠道名匹配，配置改名后按类别兜底）
	var ep GenerationEndpoint
	found := false
	for _, e := range loadEndpoints() {
		if e.Name == channel {
			ep, found = e, true
			break
		}
	}
	if !found {
		ep, err = selectEndpoint(nsfw == 1)
		if err != nil {
			markTaskFailed(recordID, err.Error())
			return
		}
	}
	if model == "" {
		model = ep.Model
	}
	client := services.NewGrokClient(ep.APIURL, ep.APIKey)
	resp, err := client.Generate(services.GenRequest{
		Prompt:         prompt,
		Model:          model,
		N:              n,
		AspectRatio:    ratio,
		Resolution:     res,
		ResponseFormat: format,
	})
	if err != nil {
		markTaskFailed(recordID, truncateRunes("生成失败："+err.Error(), 250))
		return
	}

	// 上游返回 200 但没有任何图片内容时视为失败：绝不保留"空成功"
	hasImage := false
	for _, d := range resp.Data {
		if d.URL != "" || d.B64 != "" {
			hasImage = true
			break
		}
	}
	if !hasImage {
		markTaskFailed(recordID, "生成服务未返回图片内容，积分已退回，请重试")
		return
	}

	// 落盘每一张图，首图兼作记录封面；若配置了外部长期存储
	// （s3/webdav/post），同步上传并把存储方式与远端路径记入库，
	// 服务器本地文件被清理后仍可通过备用地址访问。
	imageURL := ""
	storageType := ""
	storageRefByID := map[int]string{}
	savedAny := false
	for i := range resp.Data {
		item := resp.Data[i]
		src := item.URL
		if src == "" && item.B64 != "" {
			src = "data:image/png;base64," + item.B64
		} else if src != "" {
			// 部分网关在响应里回带自身回环/内网地址（如 127.0.0.1:8000），
			// 应用服务器与浏览器都无法直连：改写为渠道网关的公网主机再下载，
			// 并同步修正落库地址，避免缩略图裂图。
			src = rewriteLoopbackURL(src, ep.APIURL)
			resp.Data[i].URL = src
		}
		if saved, err := saveImageLocally(src, client); err == nil {
			savedAny = true
			resp.Data[i].URL = saved
			resp.Data[i].B64 = ""
			if i == 0 {
				imageURL = saved
			}
			// 外部存储上传（失败仅告警，不影响本地归档）
			// 注意：storage_path 落库的是完整可访问地址（result.URL），
			// S3/POST 模式绝不能存相对 Ref（前端备用下载/图片回退会 404）。
			if up := getUploader(); up != nil {
				if result, uerr := up.Upload("data"+saved, strings.TrimPrefix(saved, "/images/")); uerr == nil {
					storageType = storageTypeOf()
					storageRefByID[i] = result.URL
					log.Printf("image %s uploaded to storage ref=%s url=%s", saved, result.Ref, result.URL)
				} else {
					log.Printf("storage upload failed for %s: %v", saved, uerr)
				}
			}
		}
	}
	// 全部图片都未成功归档（下载失败/解码失败）时绝不保留"空成功"：
	// 标记失败并退回积分，避免出现"成功但无图"的任务与裂图缩略图。
	if !savedAny {
		markTaskFailed(recordID, "生成成功但图片归档失败，积分已退回，请重试")
		return
	}
	updRes, _ := models.DB.Exec("UPDATE generation_records SET status='success', image_url=?, channel=? WHERE id=? AND status='processing'",
		imageURL, ep.Name, recordID)
	if rowsAffected(updRes) == 0 {
		return // 记录不在了或已被并发处理，不归档图片
	}
	for i := range resp.Data {
		p := resp.Data[i].URL
		if p != "" {
			ref := storageRefByID[i]
			models.DB.Exec("INSERT INTO generation_images(record_id, idx, path, storage_type, storage_path) VALUES(?,?,?,?,?)",
				recordID, i, p, storageType, ref)
		}
	}
}

func rowsAffected(r sql.Result) int64 {
	if r == nil {
		return 0
	}
	n, _ := r.RowsAffected()
	return n
}

// markTaskFailed 把任务标记为失败并退回本次扣费（幂等：仅处理中任务生效）。
func markTaskFailed(recordID int64, msg string) {
	var userID, cost int64
	if err := models.DB.QueryRow("SELECT user_id, cost_points FROM generation_records WHERE id=?", recordID).Scan(&userID, &cost); err != nil {
		log.Printf("markTaskFailed %d: %v", recordID, err)
		return
	}
	if rowsAffected(mustExec("UPDATE generation_records SET status='failed', error_msg=? WHERE id=? AND status='processing'", truncateRunes(msg, 300), recordID)) == 0 {
		return
	}
	mustExec("UPDATE users SET points = points + ? WHERE id=?", cost, userID)
	logPoints(userID, cost, "生成失败，积分退回")
}

// cleanUpTask 执行一次自动清理：同时受"保留天数"与"磁盘上限"两个规则
// 约束，任一规则触发都会清理；两者都未启用时直接跳过。
// 规则（后台设置）：
//   - cleanup_enabled  总开关（true 才执行）
//   - cleanup_keep_days  超过该天数的旧记录会被清理（本地文件删除；
//     已上传外部存储的图片保留记录与备用地址，仅移除本地文件）
//   - cleanup_max_mb    data/images 目录超过该大小（MB）时，按旧到新
//     删除本地图片文件直到低于上限
func cleanUpTask() {
	if v, _ := models.GetConfig("cleanup_enabled"); v != "true" {
		return
	}
	keepDays := atoiDefault(models.GetConfigOr("cleanup_keep_days", "30"), 30)
	maxMB := atoiDefault(models.GetConfigOr("cleanup_max_mb", "2048"), 2048)
	now := time.Now()
	cutoff := now.AddDate(0, 0, -keepDays)

	// ---------- 规则一：按保留天数 ----------
	// 找出超期记录：本地文件未上传外部存储的直接删记录+文件；
	// 已上传外部存储的保留记录（备用地址仍可用），仅删本地文件。
	rows, err := models.DB.Query(`SELECT gr.id, gi.path, gi.storage_path
		FROM generation_records gr
		LEFT JOIN generation_images gi ON gi.record_id = gr.id
		WHERE julianday(gr.created_at) < julianday(?) AND gr.status = 'success'`, cutoff.UTC().Format(time.RFC3339))
	if err == nil {
		type doomed struct {
			rid   int64
			paths []string
			refs  []string
		}
		byRid := map[int64]*doomed{}
		for rows.Next() {
			var rid int64
			var p, ref string
			if rows.Scan(&rid, &p, &ref) != nil {
				continue
			}
			d := byRid[rid]
			if d == nil {
				d = &doomed{rid: rid}
				byRid[rid] = d
			}
			if p != "" {
				d.paths = append(d.paths, p)
			}
			if ref != "" {
				d.refs = append(d.refs, ref)
			}
		}
		rows.Close()
		for _, d := range byRid {
			removeLocalFiles(d.paths)
			if len(d.refs) == 0 {
				// 无外部存储备份：记录一并删除
				models.DB.Exec("DELETE FROM generation_records WHERE id=?", d.rid)
				models.DB.Exec("DELETE FROM generation_images WHERE record_id=?", d.rid)
				log.Printf("cleanup: removed expired record %d", d.rid)
			} else {
				// 有外部存储：仅清空本地图片路径（记录保留，备用地址可用）
				models.DB.Exec("UPDATE generation_images SET path='' WHERE record_id=?", d.rid)
				log.Printf("cleanup: removed local files for record %d (remote backup kept)", d.rid)
			}
		}
	}

	// ---------- 规则二：按磁盘上限 ----------
	dirSize, err := dirSizeMB("data/images")
	if err != nil || dirSize <= int64(maxMB) {
		return
	}
	over := dirSize - int64(maxMB)
	// 从最旧的记录开始删，直到释放超过上限的部分
	rows2, err := models.DB.Query(`SELECT gr.id, gi.path, gi.storage_path, gi.id AS gi_id
		FROM generation_records gr
		JOIN generation_images gi ON gi.record_id = gr.id
		WHERE gr.status = 'success' AND gi.path != ''
		ORDER BY gr.created_at ASC, gr.id ASC`)
	if err == nil {
		freed := int64(0)
		type imgAsset struct {
			giID      int64
			path      string
			recordID  int64
			hasRemote bool
		}
		for rows2.Next() {
			if freed >= over {
				break
			}
			var rid, giID int64
			var p, ref string
			if rows2.Scan(&rid, &p, &ref, &giID) != nil {
				continue
			}
			sz := fileSize("data" + p)
			removeLocalFiles([]string{p})
			if ref != "" {
				models.DB.Exec("UPDATE generation_images SET path='' WHERE id=?", giID)
			} else {
				models.DB.Exec("DELETE FROM generation_images WHERE id=?", giID)
				// 该记录的图片已全部清理 → 删记录
				var cnt int
				models.DB.QueryRow("SELECT COUNT(*) FROM generation_images WHERE record_id=?", rid).Scan(&cnt)
				if cnt == 0 {
					models.DB.Exec("DELETE FROM generation_records WHERE id=?", rid)
				}
			}
			freed += sz
		}
		rows2.Close()
		if freed > 0 {
			log.Printf("cleanup: freed %d MB local images (over limit %d MB)", freed/1048576, maxMB)
		}
	}
}

// removeLocalFiles 删除一批本地图片文件（忽略不存在/失败）。
func removeLocalFiles(paths []string) {
	for _, p := range paths {
		if strings.HasPrefix(p, "/images/") {
			os.Remove("data" + p)
		}
	}
}

// dirSizeMB 返回目录总字节数（MB整数）。
func dirSizeMB(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
	}
	return total / 1048576, nil
}

// fileSize 返回文件字节数，失败返回 0。
func fileSize(p string) int64 {
	if info, err := os.Stat(p); err == nil {
		return info.Size()
	}
	return 0
}

// cleanupLoop 定时执行自动清理（每小时一次；启动后先跑一遍）。
func cleanupLoop() {
	time.Sleep(30 * time.Second) // 等服务就绪
	cleanUpTask()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cleanUpTask()
	}
}

// mustExec 执行一条写语句，错误仅记录日志（调用方多为幂等补偿操作）。
func mustExec(q string, args ...interface{}) sql.Result {
	res, err := models.DB.Exec(q, args...)
	if err != nil {
		log.Printf("db exec: %v", err)
	}
	return res
}

// generateStatusHandler 是异步任务的状态轮询接口：传 ids 返回对应任务详情，
// 同时附带最近 3 条任务，一次请求同时刷新创作页的进度卡与最近任务列表。
func generateStatusHandler(w http.ResponseWriter, r *http.Request) {
	uid, _, _ := currentUser(r)
	ids := []int64{}
	for _, s := range strings.Split(r.URL.Query().Get("ids"), ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && id > 0 {
			ids = append(ids, id)
		}
		if len(ids) >= 20 {
			break
		}
	}
	tasks := []map[string]interface{}{}
	for _, id := range ids {
		var prompt, status, errMsg, createdAt, imageURL string
		var n int
		if err := models.DB.QueryRow(`SELECT prompt, n, status, image_url, error_msg, created_at
			FROM generation_records WHERE id=? AND user_id=?`, id, uid).
			Scan(&prompt, &n, &status, &imageURL, &errMsg, &createdAt); err != nil {
			continue
		}
		tasks = append(tasks, map[string]interface{}{
			"ID":        id,
			"Prompt":    prompt,
			"N":         n,
			"Status":    status,
			"ImageURL":  imageURL,
			"Error":     errMsg,
			"Images":    recordImagePaths(id),
			"CreatedAt": localTime(createdAt),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	noStore(w)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks":  tasks,
		"recent": recentTasks(uid, 3),
	})
}

// likeEscape neutralizes LIKE wildcards in user-supplied search terms so that
// `%`, `_` and `\` are matched literally (used with a `LIKE ? ESCAPE '\'`).
func likeEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func recordsHandler(w http.ResponseWriter, r *http.Request) {
	userID, _, _ := currentUser(r)
	const perPage = 20
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	if page < 1 {
		page = 1
	}
	base := "WHERE user_id=?"
	args := []interface{}{userID}
	if q != "" {
		base += " AND prompt LIKE ? ESCAPE '\\'"
		args = append(args, "%"+likeEscape(q)+"%")
	}
	var total int
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records "+base, args...).Scan(&total)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	rows, err := models.DB.Query("SELECT id, prompt, model, n, aspect_ratio, resolution, cost_points, status, image_url, error_msg, channel, created_at FROM generation_records "+base+" ORDER BY id DESC LIMIT ? OFFSET ?",
		append(args, perPage, (page-1)*perPage)...)
	if err != nil {
		http.Error(w, "查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	recs := []map[string]interface{}{}
	for rows.Next() {
		var rec models.GenerationRecord
		var errMsg, channel string
		if err := rows.Scan(&rec.ID, &rec.Prompt, &rec.Model, &rec.N, &rec.AspectRatio, &rec.Resolution, &rec.CostPoints, &rec.Status, &rec.ImageURL, &errMsg, &channel, &rec.CreatedAt); err == nil {
			recs = append(recs, map[string]interface{}{
				"ID":          rec.ID,
				"Prompt":      rec.Prompt,
				"Model":       rec.Model,
				"N":           rec.N,
				"AspectRatio": rec.AspectRatio,
				"Resolution":  rec.Resolution,
				"CostPoints":  rec.CostPoints,
				"Status":      rec.Status,
				"ImageURL":    rec.ImageURL,
				"ErrorMsg":    errMsg,
				"Channel":     channel,
				"CreatedAt":   rec.CreatedAt.In(beijingTZ).Format("2006-01-02 15:04:05"),
			})
		}
	}
	// 拉取本页记录的全部归档图片（用于封面下的多图回看），
	// 同时带出外部存储信息（storage_type/storage_path），供前端
	// "备用下载"按钮与本地缓存回退使用。
	imgMap := map[int64][]string{}
	altMap := map[int64][]string{}
	subArgs := append(append([]interface{}{}, args...), perPage, (page-1)*perPage)
	rowsI, err := models.DB.Query("SELECT record_id, path, storage_path FROM generation_images WHERE record_id IN (SELECT id FROM generation_records "+base+" ORDER BY id DESC LIMIT ? OFFSET ?) ORDER BY record_id, idx", subArgs...)
	if err == nil {
		defer rowsI.Close()
		for rowsI.Next() {
			var rid int64
			var p, sp string
			if rowsI.Scan(&rid, &p, &sp) == nil {
				if p != "" {
					imgMap[rid] = append(imgMap[rid], p)
				} else if sp != "" {
					// 本地文件已清理但存在外部备份：仍以远端地址展示
					imgMap[rid] = append(imgMap[rid], sp)
				}
				if sp != "" {
					altMap[rid] = append(altMap[rid], sp)
				}
			}
		}
	}
	for _, rec := range recs {
		paths := imgMap[rec["ID"].(int64)]
		rec["Images"] = paths
		if len(paths) > 1 {
			rec["ImagesSub"] = paths[1:]
		} else {
			rec["ImagesSub"] = []string{}
		}
		rec["AltURLs"] = altMap[rec["ID"].(int64)]
	}
	// 累计消耗只统计成功/进行中的记录：失败任务的扣费已退回（见
	// markTaskFailed），若一并计入会让"累计消耗"虚高。搜索过滤保持一致。
	var totalCost int64
	costArgs := append([]interface{}{}, userID)
	costSQL := "SELECT COALESCE(SUM(cost_points),0) FROM generation_records WHERE user_id=? AND status != 'failed'"
	if q != "" {
		costSQL += " AND prompt LIKE ? ESCAPE '\\'"
		costArgs = append(costArgs, "%"+likeEscape(q)+"%")
	}
	models.DB.QueryRow(costSQL, costArgs...).Scan(&totalCost)
	pageBase := "/records?"
	if q != "" {
		pageBase += "q=" + url.QueryEscape(q) + "&"
	}
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":      "创作记录",
		"Query":      q,
		"Records":    recs,
		"TotalCost":  totalCost,
		"Page":       page,
		"TotalPages": totalPages,
		"Total":      total,
		"HasPrev":    page > 1,
		"HasNext":    page < totalPages,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"PageBase":   pageBase,
		"Content":    "content-records",
	})
}

func recordDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/records", http.StatusSeeOther)
		return
	}
	userID, _, _ := currentUser(r)
	id := r.FormValue("id")
	// 先收集该记录的全部归档图片路径与外部存储地址，再删除，避免残留文件/对象
	var paths, remoteRefs []string
	rowsP, _ := models.DB.Query("SELECT path, storage_path FROM generation_images WHERE record_id=?", id)
	if rowsP != nil {
		for rowsP.Next() {
			var p, sp string
			if rowsP.Scan(&p, &sp) == nil {
				if p != "" {
					paths = append(paths, p)
				}
				if sp != "" {
					remoteRefs = append(remoteRefs, sp)
				}
			}
		}
		rowsP.Close()
	}
	result, err := models.DB.Exec("DELETE FROM generation_records WHERE id=? AND user_id=?", id, userID)
	if err != nil {
		http.Error(w, "删除失败", http.StatusInternalServerError)
		return
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		http.Error(w, "记录不存在", http.StatusNotFound)
		return
	}
	models.DB.Exec("DELETE FROM generation_images WHERE record_id=?", id)
	for _, p := range paths {
		if strings.HasPrefix(p, "/images/") {
			os.Remove("data" + p)
		}
	}
	// 同步删除外部存储对象（尽力而为：失败仅告警，不阻塞用户操作，
	// POST 上传类型不支持远端删除时自然跳过）
	if deleter, ok := getUploader().(services.RemoteDeleter); ok {
		for _, ref := range remoteRefs {
			if err := deleter.Delete(ref); err != nil {
				log.Printf("remote delete failed for %s: %v", ref, err)
			}
		}
	}
	// 返回来源页，尽量保留分页与搜索条件
	target := "/records"
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			qp := u.Query()
			if p := qp.Get("page"); p != "" {
				target += "?page=" + p
			}
			if byQ := qp.Get("q"); byQ != "" {
				sep := "?"
				if strings.Contains(target, "?") {
					sep = "&"
				}
				target += sep + "q=" + url.QueryEscape(byQ)
			}
		}
	}
	flashRedirect(w, r, target, "已删除该创作记录")
}

// renderRedeem 渲染积分兑换页。错误（msgType=="error"）以红色文字显示在兑换码
// 输入框下方，成功（"success"）以绿色提示条显示在顶部；始终停留在兑换页本身，
// 不跳转其它页面。code 用于出错时回填输入框，避免用户重输 32 位兑换码。
func renderRedeem(w http.ResponseWriter, r *http.Request, msg, msgType, code string) {
	userID, _, _ := currentUser(r)
	data := map[string]interface{}{
		"Title":       "积分兑换",
		"Message":     msg,
		"MessageType": msgType,
		"Code":        code,
		"History":     redeemHistory(userID),
		"Content":     "content-redeem",
	}
	renderPage(w, r, "layout.html", data)
}

// redeemHistory lists the user's recent successful redemptions (code, points, time).
func redeemHistory(userID int64) []map[string]interface{} {
	var hist []map[string]interface{}
	rows, err := models.DB.Query(`SELECT code, points, used_at FROM redeem_codes
		WHERE used_by=? AND status='used' ORDER BY used_at DESC LIMIT 5`, userID)
	if err != nil {
		return hist
	}
	defer rows.Close()
	for rows.Next() {
		var code string
		var pts int64
		var usedAt string
		if rows.Scan(&code, &pts, &usedAt) == nil {
			hist = append(hist, map[string]interface{}{"Code": code, "Points": pts, "UsedAt": localTime(usedAt)})
		}
	}
	return hist
}

func redeemHandler(w http.ResponseWriter, r *http.Request) {
	userID, username, _ := currentUser(r)
	if r.Method == http.MethodPost {
		// 异步请求返回 JSON（前端原地显示错误、不刷新页面），普通请求整页渲染。
		if !verifyCSRF(r) {
			if ajaxRequest(r) {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "表单已过期，请刷新页面后重试"})
				return
			}
			renderError(w, r, "400", "表单已过期，请刷新页面后重试")
			return
		}
		code := strings.ToUpper(strings.TrimSpace(r.FormValue("code")))
		fail := func(msg string) {
			if ajaxRequest(r) {
				writeJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "error": msg})
				return
			}
			renderRedeem(w, r, msg, "error", code)
		}
		if code == "" || len(code) > 32 {
			msg := "兑换码无效或已被使用"
			if code == "" {
				msg = "请输入兑换码"
			}
			fail(msg)
			return
		}
		var points int64
		err := models.DB.QueryRow("SELECT points FROM redeem_codes WHERE code=? AND status='active' AND (kind='' OR kind='points')", code).Scan(&points)
		if err != nil {
			fail("兑换码无效或已被使用")
			return
		}
		fail500 := func() {
			if ajaxRequest(r) {
				writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": "兑换失败，请稍后重试"})
				return
			}
			http.Error(w, "兑换失败，请稍后重试", http.StatusInternalServerError)
		}
		tx, err := models.DB.Begin()
		if err != nil {
			fail500()
			return
		}
		if _, e1 := tx.Exec("UPDATE users SET points = points + ? WHERE id=?", points, userID); e1 != nil {
			tx.Rollback()
			fail500()
			return
		}
		res2, e2 := tx.Exec("UPDATE redeem_codes SET status='used', used_by=?, used_at=CURRENT_TIMESTAMP WHERE code=?", userID, code)
		if e2 != nil {
			tx.Rollback()
			fail500()
			return
		}
		if n, _ := res2.RowsAffected(); n == 0 {
			// 并发下已被其他请求兑换：整体回滚，绝不重复发放积分
			tx.Rollback()
			fail("兑换码已被使用")
			return
		}
		if err := tx.Commit(); err != nil {
			fail500()
			return
		}
		logPoints(userID, points, "兑换码兑换获得")
		systemLog(r, userID, username, "redeem", fmt.Sprintf("兑换 %d 积分", points), points)
		if ajaxRequest(r) {
			var now int64
			models.DB.QueryRow("SELECT points FROM users WHERE id=?", userID).Scan(&now)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"ok":      true,
				"msg":     fmt.Sprintf("兑换成功，获得 %d 积分", points),
				"points":  now,
				"history": redeemHistory(userID),
			})
			return
		}
		renderRedeem(w, r, fmt.Sprintf("兑换成功，获得 %d 积分", points), "success", "")
		return
	}
	renderRedeem(w, r, "", "", "")
}

func pointsHandler(w http.ResponseWriter, r *http.Request) {
	userID, _, _ := currentUser(r)
	const perPage = 20
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	if page < 1 {
		page = 1
	}
	var total int
	models.DB.QueryRow("SELECT COUNT(*) FROM points_log WHERE user_id=?", userID).Scan(&total)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	rows, err := models.DB.Query("SELECT delta, balance, description, created_at FROM points_log WHERE user_id=? ORDER BY id DESC LIMIT ? OFFSET ?", userID, perPage, (page-1)*perPage)
	if err != nil {
		http.Error(w, "查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var entries []map[string]interface{}
	for rows.Next() {
		var delta, balance int64
		var desc, createdAt string
		if rows.Scan(&delta, &balance, &desc, &createdAt) == nil {
			entries = append(entries, map[string]interface{}{
				"Delta":     delta,
				"Balance":   balance,
				"Desc":      desc,
				"CreatedAt": localTime(createdAt),
			})
		}
	}
	var totalGot, totalUsed int64
	models.DB.QueryRow("SELECT COALESCE(SUM(CASE WHEN delta>0 THEN delta ELSE 0 END),0), COALESCE(SUM(CASE WHEN delta<0 THEN -delta ELSE 0 END),0) FROM points_log WHERE user_id=?", userID).Scan(&totalGot, &totalUsed)
	var userSince string
	models.DB.QueryRow("SELECT strftime('%Y-%m-%d', created_at) FROM users WHERE id=?", userID).Scan(&userSince)
	var checkinCount, recordCount int
	models.DB.QueryRow("SELECT COUNT(*) FROM checkin_logs WHERE user_id=?", userID).Scan(&checkinCount)
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE user_id=? AND status='success'", userID).Scan(&recordCount)
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":        "积分明细",
		"Log":          entries,
		"TotalGot":     totalGot,
		"TotalUsed":    totalUsed,
		"NetGain":      totalGot - totalUsed,
		"UserSince":    userSince,
		"CheckinCount": checkinCount,
		"RecordCount":  recordCount,
		"Page":         page,
		"TotalPages":   totalPages,
		"Total":        total,
		"HasPrev":      page > 1,
		"HasNext":      page < totalPages,
		"PrevPage":     page - 1,
		"NextPage":     page + 1,
		"PageBase":     "/points?",
		"Content":      "content-points",
	})
}

func renderPassword(w http.ResponseWriter, r *http.Request, errMsg, okMsg string) {
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":   "修改密码",
		"Error":   errMsg,
		"Success": okMsg,
		"Content": "content-password",
	})
}

func passwordHandler(w http.ResponseWriter, r *http.Request) {
	userID, _, _ := currentUser(r)
	var oauthProvider string
	models.DB.QueryRow("SELECT oauth_provider FROM users WHERE id=?", userID).Scan(&oauthProvider)
	if oauthProvider != "" {
		// 第三方登录账号的密码由平台侧管理，闭环提示而非报错
		renderPassword(w, r, "", "该账号由第三方平台（Linux.do）负责登录，密码无需在此修改")
		return
	}
	if r.Method == http.MethodPost {
		if !verifyCSRF(r) {
			renderError(w, r, "400", "表单已过期，请刷新页面后重试")
			return
		}
		var oldHash string
		models.DB.QueryRow("SELECT password_hash FROM users WHERE id=?", userID).Scan(&oldHash)
		oldPw := r.FormValue("old_password")
		newPw := r.FormValue("new_password")
		if bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(oldPw)) != nil {
			renderPassword(w, r, "原密码不正确", "")
			return
		}
		if len(newPw) < 6 {
			renderPassword(w, r, "新密码长度至少 6 位", "")
			return
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(newPw), bcrypt.DefaultCost)
		if err != nil {
			renderPassword(w, r, "密码加密失败，请重试", "")
			return
		}
		if _, err := models.DB.Exec("UPDATE users SET password_hash=? WHERE id=?", string(hashed), userID); err != nil {
			renderPassword(w, r, "保存失败，请重试", "")
			return
		}
		renderPassword(w, r, "", "密码修改成功，下次登录请使用新密码")
		return
	}
	renderPassword(w, r, "", "")
}

func checkinHandler(w http.ResponseWriter, r *http.Request) {
	userID, username, _ := currentUser(r)
	enabled, _ := models.GetConfig("enable_daily_checkin")

	if r.Method == http.MethodPost {
		if !verifyCSRF(r) {
			renderError(w, r, "400", "表单已过期，请刷新页面后重试")
			return
		}
		if enabled != "true" {
			renderPage(w, r, "layout.html", map[string]interface{}{
				"Title":          "每日签到",
				"Error":          "签到功能暂未开启",
				"CheckinEnabled": enabled,
				"Content":        "content-checkin",
			})
			return
		}
		today := time.Now().Format("2006-01-02")
		var count int
		models.DB.QueryRow("SELECT COUNT(*) FROM checkin_logs WHERE user_id=? AND date=?", userID, today).Scan(&count)
		if count > 0 {
			flashRedirect(w, r, "/checkin", "今日已签到，明天再来吧")
			return
		}
		mode, _ := models.GetConfig("checkin_mode")
		points := 0
		if mode == "random" {
			min := atoiDefault(models.GetConfigOr("checkin_random_min", "1"), 1)
			max := atoiDefault(models.GetConfigOr("checkin_random_max", "20"), 20)
			if max < min {
				max = min
			}
			// 用加密级随机源取值，杜绝按纳秒推算的漏洞（公平性）
			span := uint64(max - min + 1)
			var buf [8]byte
			if _, err := rand.Read(buf[:]); err == nil {
				points = min + int(binary.BigEndian.Uint64(buf[:])%span)
			} else {
				points = min
			}
		} else {
			points = atoiDefault(models.GetConfigOr("checkin_fixed_points", "10"), 10)
		}
		// 事务内加积分并落签到记录，避免双击 / 并发造成重复发放
		tx, err := models.DB.Begin()
		if err != nil {
			http.Error(w, "系统繁忙，请重试", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec("UPDATE users SET points = points + ? WHERE id=?", points, userID); err != nil {
			tx.Rollback()
			http.Error(w, "签到失败，请重试", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec("INSERT INTO checkin_logs(user_id, date, points) VALUES(?,?,?)", userID, today, points); err != nil {
			// 唯一约束冲突：已在其他请求中签到，放弃本次发放
			tx.Rollback()
			flashRedirect(w, r, "/checkin", "今日已签到，明天再来吧")
			return
		}
		if err := tx.Commit(); err != nil {
			http.Error(w, "签到失败，请重试", http.StatusInternalServerError)
			return
		}
		logPoints(userID, int64(points), "每日签到获得")
		systemLog(r, userID, username, "checkin", fmt.Sprintf("签到获得 %d 积分", points), int64(points))
		renderPage(w, r, "layout.html", map[string]interface{}{
			"Title":          "每日签到",
			"CheckedIn":      true,
			"CheckinPoints":  points,
			"CheckinEnabled": enabled,
			"Streak":         checkinStreak(userID),
			"TotalCheckins":  checkinTotal(userID),
			"History":        checkinHistory(userID),
			"Days":           checkinCalendar(userID),
			"Content":        "content-checkin",
		})
		return
	}

	today := time.Now().Format("2006-01-02")
	var count int
	models.DB.QueryRow("SELECT COUNT(*) FROM checkin_logs WHERE user_id=? AND date=?", userID, today).Scan(&count)
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":          "每日签到",
		"CheckedIn":      count > 0,
		"CheckinEnabled": enabled,
		"ExpectedPoint":  expectedCheckin(),
		"Streak":         checkinStreak(userID),
		"TotalCheckins":  checkinTotal(userID),
		"History":        checkinHistory(userID),
		"Days":           checkinCalendar(userID),
		"Content":        "content-checkin",
	})
}

func checkinTotal(uid int64) int {
	var n int
	models.DB.QueryRow("SELECT COUNT(*) FROM checkin_logs WHERE user_id=?", uid).Scan(&n)
	return n
}

// checkinCalendar returns the last 30 days with checkin status for the calendar grid.
func checkinCalendar(uid int64) []map[string]interface{} {
	checked := map[string]bool{}
	rows, err := models.DB.Query("SELECT date FROM checkin_logs WHERE user_id=? AND date >= date('now','-29 day','localtime')", uid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d string
			if rows.Scan(&d) == nil {
				checked[d] = true
			}
		}
	}
	days := make([]map[string]interface{}, 0, 30)
	now := time.Now()
	today := now.Format("2006-01-02")
	weekdays := []string{"日", "一", "二", "三", "四", "五", "六"}
	for i := 29; i >= 0; i-- {
		t := now.AddDate(0, 0, -i)
		dateStr := t.Format("2006-01-02")
		days = append(days, map[string]interface{}{
			"Date":    dateStr,
			"Day":     t.Format("01/02"),
			"Weekday": weekdays[int(t.Weekday())],
			"Checked": checked[dateStr],
			"Today":   dateStr == today,
		})
	}
	return days
}

func checkinHistory(uid int64) []map[string]interface{} {
	rows, err := models.DB.Query("SELECT date, points FROM checkin_logs WHERE user_id=? ORDER BY date DESC LIMIT 30", uid)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var history []map[string]interface{}
	for rows.Next() {
		var d string
		var p int
		rows.Scan(&d, &p)
		history = append(history, map[string]interface{}{"Date": d, "Points": p})
	}
	return history
}

// checkinStreak counts consecutive check-in days ending today (or yesterday
// when today is not yet checked in).
func checkinStreak(uid int64) int {
	checked := map[string]bool{}
	rows, err := models.DB.Query("SELECT date FROM checkin_logs WHERE user_id=?", uid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d string
			if rows.Scan(&d) == nil {
				checked[d] = true
			}
		}
	}
	start := time.Now()
	if !checked[start.Format("2006-01-02")] {
		start = start.AddDate(0, 0, -1)
	}
	streak := 0
	for i := 0; i < 730; i++ {
		if checked[start.AddDate(0, 0, -i).Format("2006-01-02")] {
			streak++
		} else {
			break
		}
	}
	return streak
}

func adminUsersHandler(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	const perPage = 20
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	if page < 1 {
		page = 1
	}
	clause := "FROM users"
	args := []interface{}{}
	if q != "" {
		clause += " WHERE username LIKE ? ESCAPE '\\'"
		args = append(args, "%"+likeEscape(q)+"%")
	}
	var total int
	models.DB.QueryRow("SELECT COUNT(*) "+clause, args...).Scan(&total)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	rows, err := models.DB.Query("SELECT id, username, points, role, status, created_at "+clause+" ORDER BY id DESC LIMIT ? OFFSET ?",
		append(args, perPage, (page-1)*perPage)...)
	if err != nil {
		http.Error(w, "查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type userRow struct {
		ID        int64
		Username  string
		Points    int64
		Role      string
		Status    int
		CreatedAt string
	}
	users := []userRow{}
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Points, &u.Role, &u.Status, &u.CreatedAt); err == nil {
			users = append(users, userRow{
				ID:        u.ID,
				Username:  u.Username,
				Points:    u.Points,
				Role:      u.Role,
				Status:    u.Status,
				CreatedAt: u.CreatedAt.In(beijingTZ).Format("2006-01-02 15:04:05"),
			})
		}
	}
	currentUID, _, _ := currentUser(r)
	pageBase := "/admin/users?"
	if q != "" {
		pageBase += "q=" + url.QueryEscape(q) + "&"
	}
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":      "用户管理",
		"Users":      users,
		"Query":      q,
		"CurrentID":  currentUID,
		"Page":       page,
		"TotalPages": totalPages,
		"Total":      total,
		"HasPrev":    page > 1,
		"HasNext":    page < totalPages,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"PageBase":   pageBase,
		"Content":    "content-users",
	})
}

func adminUserDisableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	cur, _, _ := currentUser(r)
	if strconv.FormatInt(cur, 10) == id {
		http.Error(w, "不能禁用当前登录的管理员账号", http.StatusBadRequest)
		return
	}
	models.DB.Exec("UPDATE users SET status=0 WHERE id=?", id)
	flashRedirect(w, r, adminUsersBack(r), "已禁用该用户")
}

func adminUserEnableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	models.DB.Exec("UPDATE users SET status=1 WHERE id=?", id)
	flashRedirect(w, r, adminUsersBack(r), "已启用该用户")
}

func adminUserPromoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	models.DB.Exec("UPDATE users SET role='admin' WHERE id=?", id)
	flashRedirect(w, r, adminUsersBack(r), "已设为管理员")
}

func adminUserDemoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	cur, _, _ := currentUser(r)
	if strconv.FormatInt(cur, 10) == id {
		http.Error(w, "不能取消自己的管理员权限", http.StatusBadRequest)
		return
	}
	var activeAdmins int
	models.DB.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin' AND status=1").Scan(&activeAdmins)
	if activeAdmins <= 1 {
		http.Error(w, "系统至少需要保留一名管理员", http.StatusBadRequest)
		return
	}
	models.DB.Exec("UPDATE users SET role='user' WHERE id=?", id)
	flashRedirect(w, r, adminUsersBack(r), "已降级为普通用户")
}

// adminUsersBack returns the users list URL, preserving the ?q= search term
// so an admin keeps their filter after performing an inline action.
func adminUsersBack(r *http.Request) string {
	target := "/admin/users"
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			qp := u.Query()
			seps := ""
			if qv := qp.Get("q"); qv != "" {
				target += "?q=" + url.QueryEscape(qv)
				seps = "&"
			}
			if p := qp.Get("page"); p != "" {
				target += seps + "page=" + p
			}
		}
	}
	return target
}

// adminAdjustPointsHandler grants or deducts points for a user, writing the
// change into the points ledger for transparency.
func adminAdjustPointsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	delta, err := strconv.ParseInt(r.FormValue("delta"), 10, 64)
	if err != nil || delta == 0 || delta > 100000 || delta < -100000 {
		http.Error(w, "积分值无效（范围 ±100000）", http.StatusBadRequest)
		return
	}
	// 扣减积分需要余额充足，避免把用户余额扣成负数（与服务端其他扣费口径一致）
	var affected int64
	if delta < 0 {
		d := -delta
		res, err := models.DB.Exec("UPDATE users SET points = points - ? WHERE id=? AND points >= ?", d, id, d)
		if err != nil {
			http.Error(w, "操作失败，请重试", http.StatusInternalServerError)
			return
		}
		affected, _ = res.RowsAffected()
		if affected == 0 {
			http.Error(w, "该用户当前积分不足，无法扣减", http.StatusBadRequest)
			return
		}
	} else {
		res, err := models.DB.Exec("UPDATE users SET points = points + ? WHERE id=?", delta, id)
		if err != nil {
			http.Error(w, "操作失败，请重试", http.StatusInternalServerError)
			return
		}
		affected, _ = res.RowsAffected()
	}
	if affected == 0 {
		http.Error(w, "未找到该用户", http.StatusBadRequest)
		return
	}
	if tid, err := strconv.ParseInt(id, 10, 64); err == nil {
		logPoints(tid, delta, "管理员调整")
	}
	flashRedirect(w, r, adminUsersBack(r), fmt.Sprintf("已调整 %d 积分", delta))
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	var users, activeUsers, todayCheckins, records, images, codes int
	models.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&users)
	models.DB.QueryRow("SELECT COUNT(*) FROM users WHERE status=1").Scan(&activeUsers)
	models.DB.QueryRow("SELECT COUNT(*) FROM checkin_logs WHERE date=?", time.Now().Format("2006-01-02")).Scan(&todayCheckins)
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records").Scan(&records)
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_images").Scan(&images)
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes").Scan(&codes)
	var codesActive, codesUsed, codesVoid int
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes WHERE status='active'").Scan(&codesActive)
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes WHERE status='used'").Scan(&codesUsed)
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes WHERE status='void'").Scan(&codesVoid)
	var issuedPoints, spentPoints int64
	models.DB.QueryRow("SELECT COALESCE(SUM(delta),0) FROM points_log WHERE delta>0").Scan(&issuedPoints)
	models.DB.QueryRow("SELECT COALESCE(SUM(-delta),0) FROM points_log WHERE delta<0").Scan(&spentPoints)

	var todayReg, todayGen int
	models.DB.QueryRow("SELECT COUNT(*) FROM users WHERE date(created_at,'localtime')=date('now','localtime')").Scan(&todayReg)
	models.DB.QueryRow("SELECT COUNT(*) FROM generation_records WHERE date(created_at,'localtime')=date('now','localtime')").Scan(&todayGen)

	// 最近动态：新的创作记录与新增用户
	var recentRecords []map[string]interface{}
	rowsRec, err := models.DB.Query("SELECT g.prompt, COALESCE(u.username,''), g.cost_points, g.created_at FROM generation_records g LEFT JOIN users u ON u.id=g.user_id ORDER BY g.id DESC LIMIT 5")
	if err == nil {
		defer rowsRec.Close()
		for rowsRec.Next() {
			var prompt, username, createdAt string
			var cost int
			if rowsRec.Scan(&prompt, &username, &cost, &createdAt) == nil {
				prompt = truncateRunes(prompt, 24)
				recentRecords = append(recentRecords, map[string]interface{}{
					"Prompt":    prompt,
					"Username":  username,
					"Cost":      cost,
					"CreatedAt": localTime(createdAt),
				})
			}
		}
	}
	var recentUsers []map[string]interface{}
	rowsU, err := models.DB.Query("SELECT username, points, role, status, created_at FROM users ORDER BY id DESC LIMIT 5")
	if err == nil {
		defer rowsU.Close()
		for rowsU.Next() {
			var username, role, createdAt string
			var points int64
			var status int
			if rowsU.Scan(&username, &points, &role, &status, &createdAt) == nil {
				recentUsers = append(recentUsers, map[string]interface{}{
					"Username":  username,
					"Points":    points,
					"Role":      role,
					"Status":    status,
					"CreatedAt": localTime(createdAt),
				})
			}
		}
	}
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":         "数据概览",
		"Users":         users,
		"ActiveUsers":   activeUsers,
		"TodayCheckins": todayCheckins,
		"TodayNewUsers": todayReg,
		"TodayGens":     todayGen,
		"Records":       records,
		"Images":        images,
		"Codes":         codes,
		"CodesActive":   codesActive,
		"CodesUsed":     codesUsed,
		"CodesVoid":     codesVoid,
		"IssuedPoints":  issuedPoints,
		"SpentPoints":   spentPoints,
		"RecentRecords": recentRecords,
		"RecentUsers":   recentUsers,
		"SecretDefault": sessionSecretDefault(),
		"Content":       "content-dashboard",
	})
}

// truncateRunes shortens a UTF-8 string to n runes, appending "…" when cut.
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func adminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	settings, _ := models.GetAllConfigs()
	m := map[string]string{}
	for k, v := range settings {
		m[k] = v
	}
	var adminName string
	models.DB.QueryRow("SELECT username FROM users WHERE role='admin' ORDER BY id LIMIT 1").Scan(&adminName)
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":              "系统设置",
		"Settings":           m,
		"AdminUsername":      adminName,
		"Endpoints":          loadEndpoints(),
		"LdoCallback":        linuxdoCallbackURL(r),
		"LdoDefaultCallback": linuxdoRequestCallback(r),
		"AppVersion":         AppVersion,
		"Content":            "content-settings",
	})
}

func adminUpdateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}
	if !verifyCSRF(r) {
		renderError(w, r, "400", "表单已过期，请刷新页面后重试")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "表单解析失败", http.StatusBadRequest)
		return
	}
	// 数值型配置项的最小合法值；非法输入一律丢弃、保留旧值
	numericMin := map[string]int{
		"generation_cost_points": 1,
		"initial_points":         0,
		"checkin_fixed_points":   1,
		"checkin_random_min":     1,
		"checkin_random_max":     1,
	}
	// 多接口渠道字段（ep_*[]）与生成接口的旧字段由 saveEndpointsFromForm
	// 统一处理，这里的通用循环跳过它们
	for key, vals := range r.Form {
		if key == "_csrf" || strings.HasPrefix(key, "ep_") || key == "generation_api_url" ||
			key == "generation_api_key" || key == "generation_model" || key == "admin_username" {
			continue
		}
		value := ""
		if len(vals) > 0 {
			value = vals[0]
		}
		// 随机签到：min 必须 <= max，否则两者都不落库
		if (key == "checkin_random_min" || key == "checkin_random_max") &&
			atoiDefault(r.Form.Get("checkin_random_min"), 1) > atoiDefault(r.Form.Get("checkin_random_max"), 1) {
			continue
		}
		if min, isNum := numericMin[key]; isNum {
			v, err := strconv.Atoi(value)
			if err != nil || v < min {
				continue // 非法或超范围数值：不落库
			}
			models.SetConfig(key, strconv.Itoa(v))
			continue
		}
		// 秘密字段不回显、不覆盖纯空值：留空 = 保持已保存的秘密
		if key == "linuxdo_client_secret" || key == "storage_password" {
			if strings.TrimSpace(value) == "" {
				continue
			}
			models.SetConfig(key, value)
			continue
		}
		models.SetConfig(key, value)
	}
	// 多接口渠道列表：ep_name[]/ep_url[]/ep_key[]/ep_model[]/ep_nsfw[]/ep_res[]
	// 解析为 JSON 存入 generation_endpoints，并回写旧字段保持兼容
	saveEndpointsFromForm(r)
	// 修改管理员用户名（校验 2-32 字符、不可与已有用户名冲突，改后同步会话）
	if name := strings.TrimSpace(r.FormValue("admin_username")); name != "" {
		var curName string
		models.DB.QueryRow("SELECT username FROM users WHERE role='admin' ORDER BY id LIMIT 1").Scan(&curName)
		if name != curName {
			if len(name) < 2 || len(name) > 32 {
				flashRedirect(w, r, "/admin/settings#basic", "管理员用户名长度需在 2-32 个字符之间")
				return
			}
			if _, err := models.DB.Exec("UPDATE users SET username=? WHERE username=?", name, curName); err != nil {
				flashRedirect(w, r, "/admin/settings#basic", "用户名已存在或修改失败")
				return
			}
			if sess, err := store.Get(r, "session"); err == nil {
				if sess.Values["username"] == curName {
					sess.Values["username"] = name
					sess.Save(r, w)
				}
			}
			uid, _, _ := currentUser(r)
			systemLog(r, uid, name, "admin_rename", "管理员用户名由 "+curName+" 修改为 "+name, 0)
		}
	}
	// 按最新存储设置重建上传器（并发安全：worker 线程可能正在读取）
	setUploader(loadStorageUploader())
	// 保存后停留在当前设置分类标签（避免跳回"基本信息"）
	// settings_pane 由页面 JS 随表单提交，非法值一律忽略
	pane := r.FormValue("settings_pane")
	switch pane {
	case "basic", "register", "checkin", "endpoints", "oauth", "storage", "cleanup", "about":
	default:
		pane = ""
	}
	target := "/admin/settings"
	if pane != "" {
		target += "#" + pane
	}
	flashRedirect(w, r, target, "设置已保存")
}

// adminSystemLogsHandler 系统日志页：记录用户行为（登录/注册/签到/创作/兑换/API
// 调用等），支持按 时间区间 / 用户名 / 行为 / 积分变动 / IP 逐项筛选，分页展示。
func adminSystemLogsHandler(w http.ResponseWriter, r *http.Request) {
	const perPage = 20
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	if page < 1 {
		page = 1
	}
	q := r.URL.Query()
	trim := func(name string) string { return strings.TrimSpace(q.Get(name)) }
	from, to := trim("from"), trim("to")
	user, act := trim("user"), trim("action")
	delta, ip := trim("delta"), trim("ip")

	where := []string{}
	args := []interface{}{}
	if from != "" {
		where = append(where, "date(created_at) >= date(?)")
		args = append(args, from)
	}
	if to != "" {
		where = append(where, "date(created_at) <= date(?)")
		args = append(args, to)
	}
	if user != "" {
		where = append(where, "username LIKE ?")
		args = append(args, "%"+user+"%")
	}
	if act != "" {
		where = append(where, "action = ?")
		args = append(args, act)
	}
	switch delta {
	case "in":
		where = append(where, "points_delta > 0")
	case "out":
		where = append(where, "points_delta < 0")
	case "none":
		where = append(where, "points_delta = 0")
	}
	if ip != "" {
		where = append(where, "ip LIKE ?")
		args = append(args, "%"+ip+"%")
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	models.DB.QueryRow("SELECT COUNT(*) FROM system_logs"+clause, args...).Scan(&total)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	list := []map[string]interface{}{}
	rows, err := models.DB.Query("SELECT id, username, action, detail, points_delta, ip, created_at FROM system_logs"+clause+" ORDER BY id DESC LIMIT ? OFFSET ?", append(args, perPage, (page-1)*perPage)...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var uname, act2, detail, ipp, created string
			var delta2 int64
			if rows.Scan(&id, &uname, &act2, &detail, &delta2, &ipp, &created) == nil {
				list = append(list, map[string]interface{}{
					"ID":          id,
					"Username":    uname,
					"Action":      act2,
					"ActionLabel": systemLogActionLabel(act2),
					"Detail":      detail,
					"Delta":       delta2,
					"IP":          ipp,
					"CreatedAt":   localTime(created),
				})
			}
		}
	}
	// 行为筛选下拉：固定顺序展示常见行为，再补出现过的其它行为（去重）
	actionOpts := []map[string]interface{}{}
	seen := map[string]bool{}
	for _, key := range []string{"login", "login_fail", "logout", "register", "checkin", "create", "redeem", "api"} {
		if label, ok := systemLogActions[key]; ok {
			actionOpts = append(actionOpts, map[string]interface{}{"Value": key, "Label": label})
			seen[key] = true
		}
	}
	aRows, err := models.DB.Query("SELECT DISTINCT action FROM system_logs ORDER BY action")
	if err == nil {
		defer aRows.Close()
		for aRows.Next() {
			var a string
			if aRows.Scan(&a) == nil && a != "" && !seen[a] {
				actionOpts = append(actionOpts, map[string]interface{}{"Value": a, "Label": systemLogActionLabel(a)})
				seen[a] = true
			}
		}
	}
	// 分页链接携带当前筛选条件（& 结尾，方便直接拼 page=）
	base := "/admin/logs?"
	var parts []string
	for k, v := range map[string]string{"from": from, "to": to, "user": user, "action": act, "delta": delta, "ip": ip} {
		if v != "" {
			parts = append(parts, k+"="+url.QueryEscape(v))
		}
	}
	if len(parts) > 0 {
		base += strings.Join(parts, "&") + "&"
	}
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":      "系统日志",
		"Logs":       list,
		"Total":      total,
		"TotalPages": totalPages,
		"Page":       page,
		"HasPrev":    page > 1,
		"HasNext":    page < totalPages,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"PageBase":   base,
		"Actions":    actionOpts,
		"QFrom":      from,
		"QTo":        to,
		"QUser":      user,
		"QAction":    act,
		"QDelta":     delta,
		"QIP":        ip,
		"Content":    "content-admin-logs",
	})
}

// ---------- 在线检测新版本 & 在线更新 ----------
// 版本发布源：GitHub Releases（构建与发布流程见 .github/workflows/build-binaries.yml
// 与 docs/release.md）。检测/更新面向原生二进制部署；容器部署走 docker compose pull。
const (
	updateRepo    = "yhw5231/online-creation-platform"
	updateAPIBase = "https://api.github.com/repos/" + updateRepo + "/releases"
	updateMaxSize = 300 << 20 // 安装包体积上限 300MB，防止异常文件拖垮磁盘
)

// updateRelease 是 GitHub Releases API（/releases/latest）响应的子集。
type updateRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// fetchLatestRelease 查询 GitHub 上最新的正式发布版本。
func fetchLatestRelease() (*updateRelease, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, updateAPIBase+"/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "online-creation-platform-updater")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			return nil, errors.New("GitHub API 请求过于频繁（每小时 60 次限额），请稍后再试")
		}
		return nil, fmt.Errorf("GitHub API 返回状态 %d", resp.StatusCode)
	}
	var rel updateRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("仓库暂无正式发布版本")
	}
	return &rel, nil
}

// updateAssetName 返回当前平台对应的发布安装包文件名；不支持的平台返回空串。
func updateAssetName(goos, goarch string) string {
	switch goos + "/" + goarch {
	case "windows/amd64":
		return "online-creation-windows-amd64.zip"
	case "windows/arm64":
		return "online-creation-windows-arm64.zip"
	case "darwin/amd64":
		return "online-creation-darwin-amd64.tar.gz"
	case "darwin/arm64":
		return "online-creation-darwin-arm64.tar.gz"
	case "linux/amd64":
		return "online-creation-linux-amd64.tar.gz"
	case "linux/arm64":
		return "online-creation-linux-arm64.tar.gz"
	}
	return ""
}

// parseVersion 把 vX.Y.Z[-prerelease] 解析为三段数字，便于逐段比较。
func parseVersion(s string) [3]int {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s = s[:i]
	}
	var v [3]int
	for i, part := range strings.SplitN(s, ".", 3) {
		if i >= 3 {
			break
		}
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n >= 0 {
			v[i] = n
		}
	}
	return v
}

// compareVersions 按三段版本号比较：a<b 返回 -1，a>b 返回 1，相等返回 0。
func compareVersions(a, b string) int {
	va, vb := parseVersion(a), parseVersion(b)
	for i := 0; i < 3; i++ {
		if va[i] < vb[i] {
			return -1
		}
		if va[i] > vb[i] {
			return 1
		}
	}
	return 0
}

// adminCheckUpdateHandler 返回当前版本与 GitHub 最新版的对比结果（JSON），
// 供设置页"关于与更新"在线检测使用。
func adminCheckUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rel, err := fetchLatestRelease()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "检测失败：" + err.Error()})
		return
	}
	cur := strings.TrimPrefix(AppVersion, "v")
	latest := strings.TrimPrefix(rel.TagName, "v")
	assetName := updateAssetName(runtime.GOOS, runtime.GOARCH)
	hasAsset := false
	for _, a := range rel.Assets {
		if a.Name == assetName {
			hasAsset = true
			break
		}
	}
	notes := strings.TrimSpace(rel.Body)
	if runes := []rune(notes); len(runes) > 3000 {
		notes = string(runes[:3000]) + "…"
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":           true,
		"current":      AppVersion,
		"latest":       rel.TagName,
		"name":         rel.Name,
		"notes":        notes,
		"html_url":     rel.HTMLURL,
		"upToDate":     compareVersions(cur, latest) >= 0,
		"hasAsset":     hasAsset,
		"assetName":    assetName,
		"in_container": inContainer(),
	})
}

// inContainer 检测当前是否运行在容器中（Docker 等）。
// 判断依据：/.dockerenv 存在（Docker 默认创建），或 cgroup 里出现
// docker/containerd 标识（部分无 /.dockerenv 的运行时兜底）。
func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		if bytes.Contains(b, []byte("docker")) || bytes.Contains(b, []byte("containerd")) {
			return true
		}
	}
	return false
}

// adminUpdateHandler 执行在线更新：下载最新版安装包 → 解压 → 生成重启脚本
// → 后台执行（先等 HTTP 响应返回，再结束旧进程、替换文件、拉起新进程）。
func adminUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "请求方式错误"})
		return
	}
	if !verifyCSRF(r) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "表单已过期，请刷新页面后重试"})
		return
	}
	if err := r.ParseForm(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "表单解析失败"})
		return
	}
	rel, err := fetchLatestRelease()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "获取新版本失败：" + err.Error()})
		return
	}
	// 已在最新版则不再重复更新（按版本号判断，防止重复执行）
	if compareVersions(strings.TrimPrefix(AppVersion, "v"), strings.TrimPrefix(rel.TagName, "v")) >= 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "当前已是最新版本，无需更新"})
		return
	}
	assetName := updateAssetName(runtime.GOOS, runtime.GOARCH)
	if assetName == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "当前平台暂不支持在线更新，请到 GitHub Releases 下载安装包"})
		return
	}
	assetURL := ""
	for _, a := range rel.Assets {
		if a.Name == assetName {
			assetURL = a.BrowserDownloadURL
			break
		}
	}
	if assetURL == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "最新发布中未找到当前平台的安装包 " + assetName + "，请到 GitHub Releases 手动下载"})
		return
	}
	exePath, err := os.Executable()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "无法定位当前程序文件，无法在线更新"})
		return
	}
	appDir := filepath.Dir(exePath)
	updDir := filepath.Join(appDir, "data", "update")
	if err := os.MkdirAll(filepath.Join(updDir, "new"), 0o755); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "无法创建更新目录：" + err.Error()})
		return
	}
	archivePath := filepath.Join(updDir, assetName)
	if err := downloadFile(assetURL, archivePath); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "下载安装包失败：" + err.Error()})
		return
	}
	if err := extractArchive(archivePath, filepath.Join(updDir, "new")); err != nil {
		os.Remove(archivePath)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "解压安装包失败：" + err.Error()})
		return
	}
	os.Remove(archivePath)
	// 定位新可执行文件：安装包内统一命名为 app / app.exe
	exeName := filepath.Base(exePath)
	newExe := filepath.Join(updDir, "new", "app")
	if runtime.GOOS == "windows" {
		newExe = filepath.Join(updDir, "new", "app.exe")
	}
	if fi, err := os.Stat(newExe); err != nil || fi.Size() < 1024*1024 {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "安装包内未找到可执行程序，已取消更新，正在回滚临时文件"})
		os.RemoveAll(updDir)
		return
	}
	// 换名跟随当前程序名（如容器内叫 main，更新后依旧叫 main）
	if exeName != "app" && exeName != "app.exe" {
		targetInNew := filepath.Join(updDir, "new", exeName)
		if err := os.Rename(newExe, targetInNew); err == nil {
			newExe = targetInNew
		}
	}
	if _, err := os.Stat(filepath.Join(updDir, "new", "templates")); err != nil {
		os.RemoveAll(updDir)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "安装包缺少 templates 目录，已取消更新"})
		return
	}
	// Windows 可执行文件运行中不可覆盖：走后台脚本（等 3 秒 →
	// 结束旧进程 → 替换文件 → 拉起新进程）。
	if runtime.GOOS == "windows" {
		scriptPath, err := writeUpdateScript(updDir, appDir, exeName, newExe, os.Getpid())
		if err != nil {
			os.RemoveAll(updDir)
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "创建更新脚本失败：" + err.Error()})
			return
		}
		launchDetached(scriptPath)
		log.Printf("update: preparing self-update to %s (asset %s, new exe %s)", rel.TagName, assetName, newExe)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"message": "已开始在线更新到 " + rel.TagName + "。应用将自动退出并重启（约 10~30 秒），请稍后刷新页面。",
		})
		return
	}
	// Linux/macOS（含容器部署）：原地替换文件后用新二进制替换进程映像。
	// 容器中应用进程是 PID 1（entrypoint.sh 以 exec 启动），映像替换后
	// 容器不会退出、无需重建，更新立即生效。
	log.Printf("update: applying self-update to %s (asset %s, new exe %s)", rel.TagName, assetName, newExe)
	applyExecUpdate(w, appDir, exePath, newExe, updDir, rel.TagName, inContainer())
}

// applyExecUpdate 执行"原地替换 + 进程映像替换"式更新（Linux/macOS）：
// 原子替换二进制 → 递归同步 templates/static → 返回响应后延迟 1.5 秒
// exec 新二进制（保证 HTTP 响应先送达浏览器）。exec 前关闭数据库，
// 释放 SQLite 文件句柄与锁，让新进程干净地重新初始化。
func applyExecUpdate(w http.ResponseWriter, appDir, exePath, newExe, updDir, newVersion string, container bool) {
	fail := func(msg string) {
		os.RemoveAll(updDir)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": msg})
	}
	// 1) 原子替换二进制：先改名到同目录临时名，再覆盖目标
	// （Linux 上 rename 覆盖正在运行的二进制文件是合法的）。
	// 容器中 /app/data 是挂载卷、与 /app 不在同一文件系统，此时 rename
	// 会报 EXDEV（invalid cross-device link），replaceExecutable 会退化为
	// "拷贝到目标目录 + 删除源文件"，保证后续同目录 rename 仍原子完成。
	tmpBin := exePath + ".new"
	if err := replaceExecutable(newExe, tmpBin); err != nil {
		fail("替换可执行文件失败：" + err.Error())
		return
	}
	if err := os.Rename(tmpBin, exePath); err != nil {
		os.Remove(tmpBin)
		fail("替换可执行文件失败：" + err.Error())
		return
	}
	// 2) 递归同步 templates / static（覆盖同名文件，新增文件补齐）
	if err := copyDirReplace(filepath.Join(updDir, "new", "templates"), filepath.Join(appDir, "templates")); err != nil {
		fail("同步模板失败：" + err.Error())
		return
	}
	if _, err := os.Stat(filepath.Join(updDir, "new", "static")); err == nil {
		if err := copyDirReplace(filepath.Join(updDir, "new", "static"), filepath.Join(appDir, "static")); err != nil {
			fail("同步静态资源失败：" + err.Error())
			return
		}
	}
	msg := "已开始在线更新到 " + newVersion + "。应用正在原地重启（容器不退出），请稍后刷新页面。"
	if container {
		msg = "已开始在线更新到 " + newVersion + "。正在原地重启当前容器（容器不会退出）。注意：容器重建后会恢复镜像版本，持久升级请执行 docker compose pull。"
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "message": msg})
	go func() {
		time.Sleep(1500 * time.Millisecond)
		os.RemoveAll(updDir)
		// 释放 SQLite 句柄/锁，避免 exec 后新进程读写冲突
		if models.DB != nil {
			models.DB.Close()
		}
		if err := execSelf(exePath, os.Args, os.Environ()); err != nil {
			log.Printf("update: exec new binary failed (files already replaced, restart manually): %v", err)
		}
	}()
}

// copyFileReplace 把 src 完整拷贝到 dst（保留权限并确保属主可读可执行，
// 防止 umask 剥掉执行位），成功后删除 src。用于跨文件系统替换文件的
// EXDEV 兜底路径。
func copyFileReplace(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	mode := fi.Mode().Perm() | 0o500
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		in.Close()
		return err
	}
	if _, err := io.Copy(out, in); err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		in.Close()
		os.Remove(dst)
		return err
	}
	if err := os.Chmod(dst, mode); err != nil {
		in.Close()
		os.Remove(dst)
		return err
	}
	// 先关源文件再删除：Windows 上删除被打开的文件会失败（"正在被另一个进程
	// 使用"），Linux 虽允许删除打开中的文件，统一先关闭更稳妥。
	if err := in.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}

// renameFile 是 os.Rename 的可替换引用：单测中注入 EXDEV 错误，即可验证
// 跨文件系统时的拷贝兜底逻辑，无需真实挂载两个文件系统。
var renameFile = os.Rename

// replaceExecutable 把 src 移动到 dst：优先原子 rename；当 src 与 dst 不在
// 同一文件系统时（容器中 /app/data 是挂载卷、与 /app 镜像层不同设备，最
// 为常见），Linux 的 rename 返回 EXDEV（invalid cross-device link），此时
// 退化为"拷贝内容到 dst + 删除源文件"。调用方应保证 dst 与最终目标在同一
// 文件系统内，使最终覆盖仍然原子。
func replaceExecutable(src, dst string) error {
	if err := renameFile(src, dst); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	return copyFileReplace(src, dst)
}

// copyDirReplace 递归把 src 目录拷贝到 dst，覆盖同名文件、补齐新文件。
func copyDirReplace(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil // 安装包内不应有符号链接，跳过
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			in.Close()
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			in.Close()
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			in.Close()
			out.Close()
			return err
		}
		if err := in.Close(); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

// downloadFile 把 URL 下载到 path（体积受 updateMaxSize 限制）。
func downloadFile(url, path string) error {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载返回状态 %d", resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, io.LimitReader(resp.Body, updateMaxSize+1)); err != nil {
		return err
	}
	if fi, err := f.Stat(); err != nil || fi.Size() > updateMaxSize {
		return errors.New("安装包体积异常（超过 300MB）")
	}
	return nil
}

// withinDir 校验 target 是否位于 dir 之内（防 zip-slip 路径穿越）。
func withinDir(dir, target string) bool {
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}

// extractArchive 解压 zip / tar.gz 安装包到 dest，所有条目做路径穿越校验。
func extractArchive(archivePath, dest string) error {
	lower := strings.ToLower(archivePath)
	if strings.HasSuffix(lower, ".zip") {
		zr, err := zip.OpenReader(archivePath)
		if err != nil {
			return err
		}
		defer zr.Close()
		for _, f := range zr.File {
			target := filepath.Join(dest, f.Name)
			if !withinDir(dest, target) {
				return errors.New("安装包包含非法路径：" + f.Name)
			}
			if f.FileInfo().IsDir() {
				if err := os.MkdirAll(target, 0o755); err != nil {
					return err
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			src, err := f.Open()
			if err != nil {
				return err
			}
			dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm()|0o600)
			if err != nil {
				src.Close()
				return err
			}
			if _, err := io.Copy(dst, src); err != nil {
				dst.Close()
				src.Close()
				return err
			}
			dst.Close()
			src.Close()
		}
		return nil
	}
	fr, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer fr.Close()
	gz, err := gzip.NewReader(fr)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		if !withinDir(dest, target) {
			return errors.New("安装包包含非法路径：" + hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)|0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(dst, tr); err != nil {
				dst.Close()
				return err
			}
			dst.Close()
		}
	}
	return nil
}

// writeUpdateScript 生成后台更新脚本：等 3 秒让 HTTP 响应返回 → 结束旧进程
// → 替换可执行文件、模板与静态资源 → 重新拉起程序。
func writeUpdateScript(updDir, appDir, exeName, newExe string, pid int) (string, error) {
	if runtime.GOOS == "windows" {
		script := filepath.Join(updDir, "do-update.cmd")
		src := "@echo off\r\n" +
			"chcp 65001 >nul\r\n" +
			"timeout /t 3 /nobreak >nul\r\n" +
			"taskkill /F /PID " + strconv.Itoa(pid) + " >nul 2>&1\r\n" +
			"timeout /t 1 /nobreak >nul\r\n" +
			"copy /Y \"" + newExe + "\" \"" + filepath.Join(appDir, exeName) + "\" >nul\r\n" +
			"xcopy /E /Y /I \"" + filepath.Join(updDir, "new", "templates") + "\" \"" + filepath.Join(appDir, "templates") + "\" >nul\r\n" +
			"xcopy /E /Y /I \"" + filepath.Join(updDir, "new", "static") + "\" \"" + filepath.Join(appDir, "static") + "\" >nul\r\n" +
			"rd /S /Q \"" + filepath.Join(updDir, "new") + "\" >nul 2>&1\r\n" +
			"start \"\" \"" + filepath.Join(appDir, exeName) + "\"\r\n"
		if err := os.WriteFile(script, []byte(src), 0o755); err != nil {
			return "", err
		}
		return script, nil
	}
	script := filepath.Join(updDir, "do-update.sh")
	src := "#!/bin/sh\n" +
		"APP_DIR=\"$(dirname \"$0\")/../..\"\n" +
		"sleep 3\n" +
		"kill -TERM " + strconv.Itoa(pid) + " 2>/dev/null\n" +
		"sleep 1\n" +
		"cp -f \"" + newExe + "\" \"" + filepath.Join(appDir, exeName) + "\"\n" +
		"cp -rf \"$(dirname \"$0\")/new/templates/.\" \"" + filepath.Join(appDir, "templates") + "\"\n" +
		"cp -rf \"$(dirname \"$0\")/new/static/.\" \"" + filepath.Join(appDir, "static") + "\"\n" +
		"cd \"$APP_DIR\"\n" +
		"nohup ./" + exeName + " > server.out.log 2>&1 &\n" +
		"rm -rf \"$(dirname \"$0\")/new\"\n"
	if err := os.WriteFile(script, []byte(src), 0o755); err != nil {
		return "", err
	}
	return script, nil
}

// launchDetached 脱离当前进程后台执行更新脚本（脚本内部先等待 3 秒，
// 确保本 HTTP 响应已送达浏览器）。
func launchDetached(path string) {
	if runtime.GOOS == "windows" {
		exec.Command("cmd", "/c", "start", "", "/b", path).Start()
		return
	}
	exec.Command("/bin/sh", "-c", "nohup '"+path+"' >/dev/null 2>&1 &").Start()
}

// saveEndpointsFromForm 把设置表单中的 ep_*[] 系列字段解析为渠道列表存入
// generation_endpoints（JSON），并同步回写旧的 generation_api_url/key/model
// （取第一个普通渠道）以保持向后兼容。API Key 留空表示沿用已保存的密钥
// （按 API 地址匹配旧配置）；地址为空的行直接被丢弃。
// 渠道编号（ep_id[]）：表单回显的已有编号原样保留（稳定编号，不随增删/排序
// 变化）；新行编号为空，在持久化计数器 endpoints_max_id 基础上 +1 分配，
// 删除渠道也不会复用旧编号（避免调用方的旧 channel 参数静默落到别的渠道）。
func saveEndpointsFromForm(r *http.Request) {
	// 表单字段名带 [] 后缀（如 ep_url[]），Go 解析后 key 原样保留括号
	urls := r.Form["ep_url[]"]
	names := r.Form["ep_name[]"]
	keys := r.Form["ep_key[]"]
	epModels := r.Form["ep_model[]"]
	nsfws := r.Form["ep_nsfw[]"]
	epRes := r.Form["ep_res[]"]
	availModels := r.Form["ep_models[]"]
	extraModels := r.Form["ep_extra_models[]"]
	epIDs := r.Form["ep_id[]"]
	oldByURL := map[string]string{}
	// 编号计数器：持久化记录已分配的最大编号，删除渠道也不回退
	maxID := atoiDefault(models.GetConfigOr("endpoints_max_id", "0"), 0)
	for _, ep := range loadEndpoints() {
		if ep.APIKey != "" {
			oldByURL[strings.TrimSpace(ep.APIURL)] = ep.APIKey
		}
		if ep.ID > maxID {
			maxID = ep.ID // 配置被手工编辑过则以现有编号为基准
		}
	}
	usedIDs := map[int]bool{}
	eps := []GenerationEndpoint{}
	for i, u := range urls {
		url := strings.TrimSpace(u)
		if url == "" {
			continue // 未填地址的行视为待删除占位行
		}
		// 稳定编号：回显编号保留；缺失/非法/重复的给新编号（max+1，不复用）
		id := 0
		if i < len(epIDs) {
			if n, err := strconv.Atoi(strings.TrimSpace(epIDs[i])); err == nil && n > 0 && !usedIDs[n] {
				id = n
			}
		}
		if id == 0 {
			maxID++
			id = maxID
		}
		usedIDs[id] = true
		name := ""
		if i < len(names) {
			name = strings.TrimSpace(names[i])
		}
		key := ""
		if i < len(keys) {
			key = strings.TrimSpace(keys[i])
		}
		if key == "" {
			key = oldByURL[url] // 留空 = 保留已保存的密钥
		} else if old, ok := oldByURL[url]; ok && key == maskKey(old) {
			key = old // 提交的是掩码回显值（前10位+*） = 密钥未修改，保留已保存的密钥
		} else if strings.Contains(key, "*") {
			// 含 * 的掩码值但找不到对应旧密钥（例如修改了 API 地址）：
			// 绝不把掩码当真实密钥落库，沿用旧密钥（可能是空）。
			key = oldByURL[url]
		}
		m := ""
		if i < len(epModels) {
			m = strings.TrimSpace(epModels[i])
		}
		nsfw := false
		if i < len(nsfws) && nsfws[i] == "1" {
			nsfw = true
		}
		// 分辨率档位：逗号/中文逗号分隔，去除空白；空输入 = 使用默认 1k,2k
		resolutions := []string{}
		if i < len(epRes) {
			for _, part := range strings.FieldsFunc(epRes[i], func(c rune) bool {
				return c == ',' || c == '，' || c == ' '
			}) {
				part = strings.TrimSpace(part)
				if part != "" && !containsString(resolutions, part) {
					resolutions = append(resolutions, part)
				}
			}
		}
		if len(resolutions) == 0 {
			resolutions = append([]string(nil), defaultResolutions...)
		}
		// 可用模型：预设多选（ep_models[]）与自定义补充（ep_extra_models[]）
		// 合并去重；逗号/中文逗号分隔，去除空白；为空则使用默认快捷模型
		ms := []string{}
		if i < len(availModels) || i < len(extraModels) {
			split := func(s string) {
				for _, part := range strings.FieldsFunc(s, func(c rune) bool {
					return c == ',' || c == '，' || c == ' '
				}) {
					part = strings.TrimSpace(part)
					if part != "" && !containsString(ms, part) {
						ms = append(ms, part)
					}
				}
			}
			if i < len(availModels) {
				split(availModels[i])
			}
			if i < len(extraModels) {
				split(extraModels[i])
			}
		}
		if len(ms) == 0 {
			ms = append([]string(nil), defaultModels...)
		}
		eps = append(eps, GenerationEndpoint{ID: id, Name: name, APIURL: url, APIKey: key, Model: m, Models: ms, NSFW: nsfw, Resolutions: resolutions})
	}
	if len(eps) == 0 {
		// 全部删除：清空多渠道与旧字段，停用生成服务
		models.SetConfig("generation_endpoints", "")
		models.SetConfig("generation_api_url", "")
		models.SetConfig("generation_api_key", "")
		models.SetConfig("generation_model", "")
		return
	}
	raw, _ := json.Marshal(eps)
	models.SetConfig("generation_endpoints", string(raw))
	models.SetConfig("endpoints_max_id", strconv.Itoa(maxID))
	// 兼容旧字段：普通渠道取第一个非 NSFW
	for _, ep := range eps {
		if !ep.NSFW {
			models.SetConfig("generation_api_url", ep.APIURL)
			models.SetConfig("generation_api_key", ep.APIKey)
			models.SetConfig("generation_model", ep.Model)
			return
		}
	}
}

// maskKey 返回密钥的前 10 个字符，其余字符以 * 掩码隐藏；
// 用于设置页回显已配置的渠道密钥，避免泄露完整密钥。
// 密钥长度不超过 10 位时原样返回。模板中通过 {{maskKey $ep.APIKey}} 调用。
func maskKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	r := []rune(s)
	if len(r) <= 10 {
		return s
	}
	return string(r[:10]) + strings.Repeat("*", len(r)-10)
}

func adminResetSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}
	if err := models.ResetConfigs(); err != nil {
		http.Error(w, "重置失败，请重试", http.StatusInternalServerError)
		return
	}
	// 重置后按新配置重建外部依赖（生成渠道按需读取 / 外部存储上传器）
	// 设置已重置为默认（storage_type 为空），必须同步重建/关闭上传器，
	// 否则重置后新生成的图片仍会继续上传旧的已关闭外部存储。
	u2 := loadStorageUploader()
	setUploader(u2)
	if u2 != nil {
		log.Println("Storage uploader enabled after reset:", storageTypeOf())
	}
	flashRedirect(w, r, "/admin/settings", "已恢复默认设置")
}

func atoiDefault(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil && v > 0 {
		return v
	}
	return def
}

// pagesAround returns a compact page-number list with first/last pins and a
// window of ±2 around the current page; 0 marks an ellipsis gap.
func pagesAround(page, total int) []int {
	if total <= 1 {
		return nil
	}
	out := []int{}
	for i := 1; i <= total; i++ {
		if i == 1 || i == total || (i >= page-2 && i <= page+2) {
			out = append(out, i)
		} else if len(out) == 0 || out[len(out)-1] != 0 {
			out = append(out, 0)
		}
	}
	return out
}

// beijingTZ 为北京时间时区（UTC+8）。中国不使用夏令时，用固定偏移即可，
// 避免依赖服务器系统时区或 tzdata。
var beijingTZ = time.FixedZone("CST", 8*60*60)

// parseStoreTime 解析 SQLite 存储的时间字符串（均为 UTC）：
// 旧驱动/旧数据为 "2006-01-02 15:04:05"，新驱动 CURRENT_TIMESTAMP /
// datetime() 输出 ISO-8601（如 "2026-08-14T02:03:18Z"）。
func parseStoreTime(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unparseable stored time %q", s)
}

// localTime parses a stored UTC timestamp string — legacy
// "2006-01-02 15:04:05" or ISO-8601 "2026-08-14T02:03:18Z" — and reformats
// it in Beijing time ("2006-01-02 15:04:05"), falling back to the raw value
// when parsing fails (e.g. legacy free-form data).
func localTime(s string) string {
	if t, err := parseStoreTime(s); err == nil {
		return t.In(beijingTZ).Format("2006-01-02 15:04:05")
	}
	return s
}

// commaFormat renders an integer with thousands separators (e.g. 1234567 → 1,234,567)
// for display; input may be int, int64 or their string representations.
func commaFormat(v interface{}) string {
	var n int64
	switch x := v.(type) {
	case int:
		n = int64(x)
	case int64:
		n = x
	case string:
		if p, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64); err == nil {
			n = p
		} else {
			return x
		}
	default:
		return fmt.Sprintf("%v", v)
	}
	neg := n < 0
	// 用 uint64 取绝对值，避免对 MinInt64 取反溢出
	var u uint64
	if neg {
		u = uint64(-(n + 1)) + 1
	} else {
		u = uint64(n)
	}
	s := strconv.FormatUint(u, 10)
	// 从右往左每三位插一个逗号
	var b strings.Builder
	mod := len(s) % 3
	for i, c := range s {
		if i > 0 && i%3 == mod {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// loadStorageUploader 读取后台"存储设置"并构造外部存储上传器；
// 未启用（storage_type 为空）时返回 nil。
func loadStorageUploader() services.Uploader {
	t, _ := models.GetConfig("storage_type")
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" || t == "none" {
		return nil
	}
	endpoint, _ := models.GetConfig("storage_endpoint")
	bucket, _ := models.GetConfig("storage_bucket")
	region, _ := models.GetConfig("storage_region")
	user, _ := models.GetConfig("storage_username")
	pass, _ := models.GetConfig("storage_password")
	prefix, _ := models.GetConfig("storage_path_prefix")
	return services.NewUploader(services.StorageConfig{
		Type:       t,
		Endpoint:   endpoint,
		Bucket:     bucket,
		Region:     region,
		Username:   user,
		Password:   pass,
		PathPrefix: prefix,
	})
}

// storageTypeOf 读取当前启用存储类型的规范值（用于落库）。
func storageTypeOf() string {
	t, _ := models.GetConfig("storage_type")
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" || t == "none" {
		return ""
	}
	return t
}

// rewriteLoopbackURL 把上游返回的图片地址中的回环/链路本地主机替换为渠道
// 网关自身的公网主机（很多网关响应里回带 127.0.0.1:8000 之类自身内网地址，
// 应用服务器与浏览器都无法直连，换成 [scheme]://[渠道公网主机]/[原路径] 即可
// 正常访问）。非 http(s) 地址、非回环地址或渠道地址解析失败时原样返回。
func rewriteLoopbackURL(rawURL, baseURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	if !isUnreachableHost(u.Hostname()) {
		return rawURL
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" {
		return rawURL
	}
	// 渠道地址本身也是回环（网关与平台同机）时没有可替换的公网主机，原样返回
	if isUnreachableHost(base.Hostname()) {
		return rawURL
	}
	u.Host = base.Host
	u.Scheme = base.Scheme
	return u.String()
}

// isUnreachableHost 判断主机名是否为应用服务器无法直连的
// 回环/链路本地地址（网关自己机器上的地址）。
func isUnreachableHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" || h == "127.0.0.1" || h == "0.0.0.0" || h == "::1" || h == "::" {
		return true
	}
	// 去掉 IPv6 的 [ ] 包裹
	h = strings.Trim(h, "[]")
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	return false
}

// saveImageLocally downloads an upstream media URL (or decodes base64) using
// the given channel client and stores it under data/images/, returning the
// local URL path on success ("" on failure).
func saveImageLocally(imageURL string, client *services.GrokClient) (string, error) {
	if imageURL == "" {
		return "", fmt.Errorf("empty image url")
	}
	os.MkdirAll("data/images", 0o755)
	if strings.HasPrefix(imageURL, "data:") {
		// embedded base64
		idx := strings.IndexByte(imageURL, ',')
		if idx < 0 {
			return "", fmt.Errorf("bad data url")
		}
		raw := imageURL[idx+1:]
		data, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", err
		}
		ext := extForBytes(data)
		fname := fmt.Sprintf("%d_%s%s", time.Now().UnixNano(), shortHex(), ext)
		local := "data/images/" + fname
		if err := os.WriteFile(local, data, 0o644); err != nil {
			return "", err
		}
		return "/images/" + fname, nil
	}
	// external URL
	if client == nil {
		return "", fmt.Errorf("no api client available")
	}
	data, err := client.DownloadFromURL(imageURL)
	if err != nil {
		return "", err
	}
	// 以真实内容为准决定扩展名：URL 后缀可能撒谎（jpg 实为 webp），
	// 配合全局 nosniff 头，后缀与字节不符会导致图片无法渲染
	ext := extForBytes(data)
	fname := fmt.Sprintf("%d_%s%s", time.Now().UnixNano(), shortHex(), ext)
	local := "data/images/" + fname
	if err := os.WriteFile(local, data, 0o644); err != nil {
		return "", err
	}
	return "/images/" + fname, nil
}

// extForBytes picks a file extension from actual image bytes so that a
// base64 payload (which may be JPEG/GIF/WebP rather than PNG) is saved with
// a truthful extension rather than a hardcoded .png.
func extForBytes(b []byte) string {
	// Go 的 http.DetectContentType 不识别 WebP，需按 RIFF/WEBP 魔数手动判断
	if len(b) >= 12 && string(b[0:4]) == "RIFF" && string(b[8:12]) == "WEBP" {
		return ".webp"
	}
	switch http.DetectContentType(b) {
	case "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/bmp":
		return ".bmp"
	case "image/png":
		return ".png"
	}
	return ".png"
}

func shortHex() string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return strconv.FormatInt(time.Now().UnixNano(), 16)[:6]
}

// linuxdoRequestCallback 按当前请求的站点地址生成 Linux.do 回调地址
// （https://<host>/auth/linuxdo/callback），不读取已保存的配置，用于：
//   - 管理后台展示“应在 Linux.do 开发者后台填写的 Callback URL”；
//   - Redirect URI 未配置时兜底使用，保证授权流程可用。
func linuxdoRequestCallback(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	scheme := "http"
	if r.TLS != nil || strings.HasPrefix(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https") {
		scheme = "https"
	}
	return scheme + "://" + host + "/auth/linuxdo/callback"
}

// linuxdoCallbackURL 返回 Linux.do OAuth 实际使用的回调地址：优先取后台已保存
// 的 Redirect URI，未配置时回退到按当前请求生成的默认回调地址。
func linuxdoCallbackURL(r *http.Request) string {
	if uri := models.GetConfigOr("linuxdo_redirect_uri", ""); uri != "" {
		return uri
	}
	return linuxdoRequestCallback(r)
}

// Linux.do Connect OAuth 2.0 / OpenID Connect 端点。
// 与 https://connect.linux.do/.well-known/openid-configuration 公布的一致：
// 注意授权/令牌接口都在 /oauth2/ 路径下（/oauth/ 路径并不存在，访问会 404
// 并显示 “Not Found / Please make sure you entered the information correctly”），
// 用户信息需用 Bearer 令牌调用 /api/user 获取（token 响应只含 access_token，
// 不直接携带用户 ID/用户名）。
// 使用 var 而非 const 便于测试注入本地测试服务器地址。
var (
	linuxdoAuthorizeURL = "https://connect.linux.do/oauth2/authorize"
	linuxdoTokenURL     = "https://connect.linux.do/oauth2/token"
	linuxdoUserInfoURL  = "https://connect.linux.do/api/user"
	linuxdoScope        = "openid profile email"
)

// Linux.do OAuth handlers

// fetchLinuxdoUser 用 access_token 调用 Linux.do 用户信息接口，返回用户数字
// ID 与用户名。Linux.do 的 token 响应只含 access_token，用户身份必须走
// /api/user（Authorization: Bearer）获取，响应形如：
//
//	{"id":12345,"sub":"...","username":"foo","login":"foo","name":"...","email":"...","avatar_url":"...","active":true,"trust_level":2}
func fetchLinuxdoUser(accessToken string) (userID int64, username, email string, err error) {
	req, err := http.NewRequest(http.MethodGet, linuxdoUserInfoURL, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", "", fmt.Errorf("用户信息接口返回 HTTP %d", resp.StatusCode)
	}
	var profile struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return 0, "", "", err
	}
	return profile.ID, profile.Username, profile.Email, nil
}

func linuxdoHandler(w http.ResponseWriter, r *http.Request) {
	if !oauthEnabled() {
		http.Error(w, "第三方登录未开启", http.StatusForbidden)
		return
	}
	clientID, _ := models.GetConfig("linuxdo_client_id")
	if clientID == "" {
		http.Error(w, "OAuth 客户端尚未配置，请先在管理后台填写 Client ID", http.StatusInternalServerError)
		return
	}
	// Redirect URI 未配置时自动使用当前站点默认回调地址，
	// 保证与 Linux.do 开发者后台填写的 Callback URL 一致即可正常授权。
	redirectURI := linuxdoCallbackURL(r)
	next := ""
	if isSafeLocalPath(r.URL.Query().Get("next")) {
		next = r.URL.Query().Get("next")
	}
	mode := r.URL.Query().Get("mode")
	session, _ := store.Get(r, "session")
	// 绑定模式：仅允许已登录用户发起，callback 时据此把 Linux.do 账号绑定到当前账号
	if mode == "bind" {
		uid, ok := session.Values["userID"].(int64)
		if !ok || uid == 0 {
			flashRedirect(w, r, "/login", "请先登录后再绑定 Linux.do 账号")
			return
		}
		session.Values["oauth_mode"] = "bind"
		session.Save(r, w)
	}
	// 随机一次性 state，防止 OAuth 响应注入/登录 CSRF
	oauthState := shortHex()
	session.Values["oauth_next"] = next
	session.Values["oauth_state"] = oauthState
	session.Save(r, w)
	authURL := linuxdoAuthorizeURL + "?" + url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {linuxdoScope},
		"state":         {oauthState},
	}.Encode()
	http.Redirect(w, r, authURL, http.StatusFound)
}

func linuxdoCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if !oauthEnabled() {
		http.Error(w, "第三方登录未开启", http.StatusForbidden)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "缺少授权码", http.StatusBadRequest)
		return
	}
	clientID, _ := models.GetConfig("linuxdo_client_id")
	clientSecret, _ := models.GetConfig("linuxdo_client_secret")
	redirectURI := linuxdoCallbackURL(r)
	if clientID == "" || clientSecret == "" {
		http.Error(w, "OAuth 客户端尚未配置", http.StatusInternalServerError)
		return
	}
	// 取回授权发起时的 next（登录后回到原页面）
	next := ""
	mode := ""
	preSession, _ := store.Get(r, "session")
	if n, _ := preSession.Values["oauth_next"].(string); isSafeLocalPath(n) {
		next = n
	}
	if m, _ := preSession.Values["oauth_mode"].(string); m != "" {
		mode = m
	}
	// 状态校验：state 必须与发起时存入会话的随机值一致（恒定时间比较，单次使用）
	got := r.URL.Query().Get("state")
	want, _ := preSession.Values["oauth_state"].(string)
	if got == "" || !secureCompare(got, want) {
		http.Error(w, "OAuth 状态校验失败，请重新尝试登录", http.StatusBadRequest)
		return
	}
	delete(preSession.Values, "oauth_state")
	preSession.Save(r, w)
	tokenURL := linuxdoTokenURL
	// 令牌交换使用带超时的独立客户端：上游异常挂起时快速失败，
	// 避免回调请求长时间占用 Web 服务连接。
	tokenClient := &http.Client{Timeout: 25 * time.Second}
	tokenReq, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
	}.Encode()))
	if err != nil {
		http.Error(w, "获取令牌失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")
	resp, err := tokenClient.Do(tokenReq)
	if err != nil {
		http.Error(w, "获取令牌失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "令牌接口异常，请稍后重试", http.StatusBadGateway)
		return
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		http.Error(w, "解析令牌响应失败", http.StatusInternalServerError)
		return
	}
	if tokenResp.AccessToken == "" {
		msg := tokenResp.ErrorDesc
		if msg == "" {
			msg = tokenResp.Error
		}
		if msg == "" {
			msg = "未返回 access_token"
		}
		http.Error(w, "获取令牌失败："+msg, http.StatusBadGateway)
		return
	}

	// Linux.do 的 token 响应只包含 access_token，用户信息需用 Bearer 令牌
	// 调用用户信息接口获取（user_id/username 不在 token 响应中）。
	userID, username, _, err := fetchLinuxdoUser(tokenResp.AccessToken)
	if err != nil {
		http.Error(w, "获取用户信息失败："+err.Error(), http.StatusBadGateway)
		return
	}
	if username == "" {
		http.Error(w, "第三方未返回用户名", http.StatusInternalServerError)
		return
	}

	// 绑定模式：把 Linux.do 账号绑定到当前已登录的用户（用户名/密码注册的账号）
	if mode == "bind" {
		uid, ok := preSession.Values["userID"].(int64)
		if !ok || uid == 0 {
			flashRedirect(w, r, "/login", "登录状态已过期，请重新登录后再绑定")
			return
		}
		// 若该 Linux.do 已绑定过其他账号，禁止重复绑定
		var boundID int64
		perr := models.DB.QueryRow("SELECT id FROM users WHERE oauth_provider='linuxdo' AND oauth_id=?", userID).Scan(&boundID)
		if perr == nil && boundID != uid {
			http.Error(w, "该 Linux.do 账号已绑定其他用户", http.StatusConflict)
			return
		}
		if perr == nil && boundID == uid {
			flashRedirect(w, r, "/profile", "已绑定该 Linux.do 账号")
			return
		}
		if _, err := models.DB.Exec("UPDATE users SET oauth_provider='linuxdo', oauth_id=? WHERE id=?", strconv.FormatInt(userID, 10), uid); err != nil {
			http.Error(w, "绑定失败，请稍后重试", http.StatusInternalServerError)
			return
		}
		delete(preSession.Values, "oauth_mode")
		preSession.Save(r, w)
		flashRedirect(w, r, "/profile", "Linux.do 绑定成功")
		return
	}

	// 登录模式：查找已绑定的用户
	var user models.User
	err = models.DB.QueryRow("SELECT id, username, password_hash, role, status, points FROM users WHERE oauth_provider='linuxdo' AND oauth_id=?", userID).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.Status, &user.Points)
	if err == nil {
		// existing user
		if user.Status != 1 {
			http.Error(w, "账号已被禁用", http.StatusForbidden)
			return
		}
		session := rotateSession(w, r)
		session.Values["userID"] = user.ID
		session.Values["username"] = user.Username
		session.Values["role"] = user.Role
		session.Save(r, w)
		flashRedirect(w, r, oauthTarget(next), "欢迎回来，"+user.Username)
		return
	}
	// 首次使用 Linux.do 登录：需开放注册且开放第三方注册，方可创建新账号
	openReg, _ := models.GetConfig("open_registration")
	thirdReg, _ := models.GetConfig("enable_thirdparty_registration")
	if openReg != "true" || thirdReg != "true" {
		http.Error(w, "第三方注册未开放，请联系管理员", http.StatusForbidden)
		return
	}
	// 首次使用 Linux.do 登录：先完成注册（用户名 + 密码），把 OAuth 身份暂存会话
	delete(preSession.Values, "oauth_mode")
	preSession.Values["oauth_pending_user_id"] = userID
	preSession.Values["oauth_pending_username"] = username
	preSession.Values["oauth_pending_next"] = next
	preSession.Save(r, w)
	http.Redirect(w, r, "/auth/linuxdo/setup", http.StatusSeeOther)
}

// oauthTarget returns the post-OAuth redirect target (toast handled by flash).
func oauthTarget(next string) string {
	if isSafeLocalPath(next) {
		return next
	}
	return "/create"
}

// linuxdoSetupHandler 完成 Linux.do 首次注册：用户需自行填写用户名和密码
// （复用 open_registration 的校验规则），注册后自动登录。
func linuxdoSetupHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	pendingUID, ok1 := session.Values["oauth_pending_user_id"].(int64)
	pendingName, ok2 := session.Values["oauth_pending_username"].(string)
	if !ok1 || pendingUID == 0 || !ok2 || pendingName == "" {
		flashRedirect(w, r, "/login", "请先通过 Linux.do 授权后再完成注册")
		return
	}
	openReg, _ := models.GetConfig("open_registration")
	thirdReg, _ := models.GetConfig("enable_thirdparty_registration")
	if openReg != "true" || thirdReg != "true" {
		flashRedirect(w, r, "/login", "第三方注册已关闭，无法完成注册")
		return
	}

	if r.Method == http.MethodPost {
		next := ""
		if n, _ := session.Values["oauth_pending_next"].(string); isSafeLocalPath(n) {
			next = n
		}
		// 异步请求返回 JSON（前端原地显示错误、不刷新页面），普通请求整页渲染。
		// renderOAuthSetup 不需要 next 参数，这里用闭包对齐 formFail 签名。
		oauthFail := func(formErr, codeErr, username string) {
			formFail(w, r, func(w http.ResponseWriter, r *http.Request, formErr, codeErr, next, username string) {
				renderOAuthSetup(w, r, formErr, codeErr, username)
			}, formErr, codeErr, next, username)
		}
		if !verifyCSRF(r) {
			if ajaxRequest(r) {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "form": "表单已过期，请刷新页面后重试"})
				return
			}
			renderError(w, r, "400", "表单已过期，请刷新页面后重试")
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		regCode := strings.ToUpper(strings.TrimSpace(r.FormValue("reg_code")))
		if len(username) < 2 || len(username) > 32 {
			oauthFail("用户名长度需在 2-32 个字符之间", "", username)
			return
		}
		if len(password) < 6 {
			oauthFail("密码长度至少 6 位", "", username)
			return
		}
		requireCode, _ := models.GetConfig("require_reg_code")
		if requireCode == "true" && regCode == "" {
			oauthFail("", "请输入注册码", username)
			return
		}
		hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		initPoints := atoiDefault(models.GetConfigOr("initial_points", "0"), 0)

		var uid int64
		if requireCode == "true" {
			// 原子占用注册码（与普通注册一致）
			tx, err := models.DB.Begin()
			if err != nil {
				if ajaxRequest(r) {
					writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "form": "系统繁忙，请重试"})
					return
				}
				http.Error(w, "系统繁忙，请重试", http.StatusInternalServerError)
				return
			}
			res, err := tx.Exec("INSERT INTO users(username, password_hash, points, role, status, oauth_provider, oauth_id) VALUES(?,?,?,?,?,?,?)",
				username, string(hashed), initPoints, "user", 1, "linuxdo", strconv.FormatInt(pendingUID, 10))
			if err != nil {
				tx.Rollback()
				oauthFail("用户名已存在或输入有误", "", username)
				return
			}
			uid, _ = res.LastInsertId()
			res2, err := tx.Exec("UPDATE redeem_codes SET status='used', used_by=?, used_at=CURRENT_TIMESTAMP WHERE code=? AND status='active' AND (kind='' OR kind='register')", uid, regCode)
			if err != nil {
				tx.Rollback()
				if ajaxRequest(r) {
					writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "form": "系统繁忙，请重试"})
					return
				}
				http.Error(w, "系统繁忙，请重试", http.StatusInternalServerError)
				return
			}
			if n, _ := res2.RowsAffected(); n == 0 {
				tx.Rollback()
				oauthFail("", "注册码无效或已被使用", username)
				return
			}
			if err := tx.Commit(); err != nil {
				if ajaxRequest(r) {
					writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "form": "系统繁忙，请重试"})
					return
				}
				http.Error(w, "系统繁忙，请重试", http.StatusInternalServerError)
				return
			}
		} else {
			res, err := models.DB.Exec("INSERT INTO users(username, password_hash, points, role, status, oauth_provider, oauth_id) VALUES(?,?,?,?,?,?,?)",
				username, string(hashed), initPoints, "user", 1, "linuxdo", strconv.FormatInt(pendingUID, 10))
			if err != nil {
				oauthFail("用户名已存在或输入有误", "", username)
				return
			}
			uid, _ = res.LastInsertId()
		}
		delete(session.Values, "oauth_pending_user_id")
		delete(session.Values, "oauth_pending_username")
		delete(session.Values, "oauth_pending_next")
		session.Save(r, w)
		if initPoints > 0 {
			logPoints(uid, int64(initPoints), "注册赠送")
		}
		systemLog(r, uid, username, "register", "Linux.do 第三方注册成功", int64(initPoints))
		s := rotateSession(w, r)
		s.Values["userID"] = uid
		s.Values["username"] = username
		s.Values["role"] = "user"
		s.Save(r, w)
		if ajaxRequest(r) {
			setFlash(w, r, "注册成功，欢迎加入，"+username)
			writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "redirect": oauthTarget(next)})
			return
		}
		flashRedirect(w, r, oauthTarget(next), "注册成功，欢迎加入，"+username)
		return
	}

	// GET：渲染“完善账号信息”表单（用户名预填 Linux.do 用户名，可修改）
	renderOAuthSetup(w, r, "", "", "")
}

// renderOAuthSetup 渲染 Linux.do 完善账号信息表单：errMsg（用户名/密码等）显示
// 在表单顶部，regCodeErr（注册码问题）以红色文字显示在注册码输入框下方；出错时
// 重渲染表单本身，不跳转到错误页面。username 为空时回填会话中的 Linux.do 用户名。
func renderOAuthSetup(w http.ResponseWriter, r *http.Request, errMsg, regCodeErr, username string) {
	session, _ := store.Get(r, "session")
	if username == "" {
		if pendingName, ok := session.Values["oauth_pending_username"].(string); ok {
			username = pendingName
		}
	}
	reqCode, _ := models.GetConfig("require_reg_code")
	noStore(w)
	err := tpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
		"Title":          "完成注册",
		"Error":          errMsg,
		"RegCodeError":   regCodeErr,
		"IsAdmin":        false,
		"IsLoggedIn":     false,
		"Points":         0,
		"RequireRegCode": reqCode == "true",
		"OAuthUsername":  username,
		"SiteName":       siteName(),
		"Toast":          consumeFlash(w, r),
		"CSRF":           csrfToken(w, r),
		"Content":        "content-oauth-setup",
	})
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// redeemCodeLabel 返回兑换码的物品名（列表展示与复制文本共用）：
// 注册码 → "注册码"；积分码 → "N积分"；旧版未分类码 → "通用"。
func redeemCodeLabel(kind string, points int64) string {
	switch kind {
	case "register":
		return "注册码"
	case "":
		return "通用"
	default:
		return fmt.Sprintf("%d积分", points)
	}
}

// redeemCodeLine 按用户约定的格式生成一行复制文本：【物品名    码】，如
// 【注册码    ABCDEFGH】、【100积分    ABCDEFGH】。
func redeemCodeLine(label, code string) string {
	return "【" + label + "    " + code + "】"
}

func adminRedeemCodesHandler(w http.ResponseWriter, r *http.Request) {
	redeemAdminPage(w, r, nil)
}

// redeemAdminPage 渲染兑换码/注册码管理页（含分页、搜索、类型/状态筛选），
// extra 可追加模板数据（如批量生成后的新码，供一键复制）。
func redeemAdminPage(w http.ResponseWriter, r *http.Request, extra map[string]interface{}) {
	// 每页条数：默认 20，可选 20/50/100/200/500/1000/2000
	const defaultPerPage = 20
	perPage := atoiDefault(r.URL.Query().Get("size"), defaultPerPage)
	switch perPage {
	case 20, 50, 100, 200, 500, 1000, 2000:
	default:
		perPage = defaultPerPage
	}
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	if page < 1 {
		page = 1
	}
	q := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("q")))
	typeFilter := r.URL.Query().Get("t")
	statusFilter := r.URL.Query().Get("s")
	conds := []string{}
	args := []interface{}{}
	if q != "" {
		conds = append(conds, "rc.code LIKE ? ESCAPE '\\'")
		args = append(args, "%"+likeEscape(q)+"%")
	}
	// 类型筛选：points = 积分兑换码（含旧版未分类码），register = 注册码
	switch typeFilter {
	case "points":
		conds = append(conds, "(rc.kind='' OR rc.kind='points')")
	case "register":
		conds = append(conds, "rc.kind='register'")
	}
	// 状态筛选：active = 可用，used = 已使用，void = 已作废
	switch statusFilter {
	case "active", "used", "void":
		conds = append(conds, "rc.status='"+statusFilter+"'")
	}
	clause := ""
	if len(conds) > 0 {
		clause = " WHERE " + strings.Join(conds, " AND ")
	}
	var total int
	models.DB.QueryRow("SELECT COUNT(*) FROM redeem_codes rc"+clause, args...).Scan(&total)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	rows, err := models.DB.Query("SELECT rc.id, rc.code, rc.points, rc.kind, rc.status, rc.used_by, rc.used_at, COALESCE(u.username,''), rc.created_at, COALESCE(rc.remark,'') FROM redeem_codes rc LEFT JOIN users u ON u.id = rc.used_by"+clause+" ORDER BY rc.id DESC LIMIT ? OFFSET ?", append(args, perPage, (page-1)*perPage)...)
	if err != nil {
		http.Error(w, "查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var codes []map[string]interface{}
	for rows.Next() {
		var id int64
		var code string
		var points int64
		var kind string
		var status string
		var usedBy sql.NullInt64
		var usedAt sql.NullTime
		var usedByName string
		var createdAt sql.NullTime
		var remark string
		if err := rows.Scan(&id, &code, &points, &kind, &status, &usedBy, &usedAt, &usedByName, &createdAt, &remark); err != nil {
			continue
		}
		usedByVal := int64(0)
		if usedBy.Valid {
			usedByVal = usedBy.Int64
		}
		usedAtStr := ""
		if usedAt.Valid {
			usedAtStr = localTime(usedAt.Time.Format("2006-01-02 15:04:05"))
		}
		createdAtStr := ""
		if createdAt.Valid {
			createdAtStr = localTime(createdAt.Time.Format("2006-01-02 15:04:05"))
		}
		label := redeemCodeLabel(kind, points)
		codes = append(codes, map[string]interface{}{
			"ID":         id,
			"Code":       code,
			"Points":     points,
			"Kind":       kind,
			"Label":      label,
			"CopyText":   redeemCodeLine(label, code),
			"Status":     status,
			"UsedBy":     usedByVal,
			"UsedByName": usedByName,
			"UsedAt":     usedAtStr,
			"CreatedAt":  createdAtStr,
			"Remark":     remark,
		})
	}
	// 筛选回链基础地址（不含 page/size，供分页与每页条数链接复用）
	filtersBase := "/admin/redeem-codes?"
	if typeFilter != "" {
		filtersBase += "t=" + url.QueryEscape(typeFilter) + "&"
	}
	if statusFilter != "" {
		filtersBase += "s=" + url.QueryEscape(statusFilter) + "&"
	}
	if q != "" {
		filtersBase += "q=" + url.QueryEscape(q) + "&"
	}
	pageBase := filtersBase + "size=" + strconv.Itoa(perPage) + "&"
	data := map[string]interface{}{
		"Title":        "兑换码管理",
		"Codes":        codes,
		"Query":        q,
		"TypeFilter":   typeFilter,
		"StatusFilter": statusFilter,
		"Page":         page,
		"TotalPages":   totalPages,
		"Total":        total,
		"HasPrev":      page > 1,
		"HasNext":      page < totalPages,
		"PrevPage":     page - 1,
		"NextPage":     page + 1,
		"PageBase":     pageBase,
		"SizeBase":     filtersBase,
		"PageSize":     perPage,
		"SizeOptions":  []int{20, 50, 100, 200, 500, 1000, 2000},
		"Content":      "content-redeem-admin",
	}
	for k, v := range extra {
		data[k] = v
	}
	renderPage(w, r, "layout.html", data)
}

func adminGenerateRedeemCodesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/redeem-codes", http.StatusSeeOther)
		return
	}
	if !verifyCSRF(r) {
		renderError(w, r, "400", "表单已过期，请刷新页面后重试")
		return
	}
	// kind：points = 积分兑换码（需填积分值）；register = 注册码（注册用，无积分）
	kind := r.FormValue("kind")
	if kind != "register" {
		kind = "points"
	}
	countStr := r.FormValue("count")
	count, err := strconv.Atoi(countStr)
	if err != nil || count <= 0 {
		http.Error(w, "生成数量无效", http.StatusBadRequest)
		return
	}
	if count > 100 {
		http.Error(w, "单次最多生成 100 个", http.StatusBadRequest)
		return
	}
	remark := strings.TrimSpace(r.FormValue("remark"))
	if rn := []rune(remark); len(rn) > 100 {
		remark = string(rn[:100])
	}
	var points int
	if kind == "points" {
		points, err = strconv.Atoi(r.FormValue("points"))
		if err != nil || points <= 0 {
			http.Error(w, "积分值无效", http.StatusBadRequest)
			return
		}
	}
	label := redeemCodeLabel(kind, int64(points))
	uid, _, _ := currentUser(r)
	consecFails := 0
	lines := []string{}
	newCodes := []map[string]interface{}{}
	for i := 0; i < count; i++ {
		code := generateRedeemCode()
		_, err := models.DB.Exec("INSERT INTO redeem_codes(code, points, kind, created_by, status, remark) VALUES(?,?,?,?,?,?)", code, points, kind, uid, "active", remark)
		if err != nil {
			// 偶发重复则重试；连续冲突过多（库故障等）时放弃，避免死循环
			consecFails++
			if consecFails > 20 {
				http.Error(w, "生成失败：冲突过多，请重试", http.StatusInternalServerError)
				return
			}
			i--
			continue
		}
		consecFails = 0
		line := redeemCodeLine(label, code)
		lines = append(lines, line)
		newCodes = append(newCodes, map[string]interface{}{"Code": code, "Line": line})
	}
	// 直接渲染页面并携带新生成的码（每行一个：【物品名    码】），
	// 管理员可立即一键复制，重复刷新不再重复生成。
	redeemAdminPage(w, r, map[string]interface{}{
		"NewCodes":  newCodes,
		"NewBulk":   strings.Join(lines, "\n"),
		"NewKind":   kind,
		"NewPoints": points,
		"NewRemark": remark,
	})
}

// adminRemarkRedeemCodesHandler 保存备注（单个或批量，ids 逗号分隔），
// 供管理员区分兑换码/注册码的用途与来源。
func adminRemarkRedeemCodesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/redeem-codes", http.StatusSeeOther)
		return
	}
	ids := splitIDList(r.FormValue("ids"))
	if len(ids) == 0 {
		flashRedirect(w, r, redeemAdminTarget(r), "请先选择要备注的兑换码")
		return
	}
	remark := strings.TrimSpace(r.FormValue("remark"))
	if rn := []rune(remark); len(rn) > 100 {
		remark = string(rn[:100])
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, remark)
	for _, id := range ids {
		args = append(args, id)
	}
	models.DB.Exec("UPDATE redeem_codes SET remark=? WHERE id IN ("+ph+")", args...)
	flashRedirect(w, r, redeemAdminTarget(r), fmt.Sprintf("已为 %d 个码保存备注", len(ids)))
}

// redeemAdminTarget 从 Referer 还原兑换码管理页的筛选/分页参数，
// 供备注、作废等操作完成后返回原位置。
func redeemAdminTarget(r *http.Request) string {
	target := "/admin/redeem-codes"
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			qp := u.Query()
			seps := ""
			if qv := qp.Get("q"); qv != "" {
				target += "?q=" + url.QueryEscape(qv)
				seps = "&"
			}
			if p := qp.Get("page"); p != "" {
				target += seps + "page=" + p
			}
		}
	}
	return target
}

// splitIDList 解析逗号分隔的 ID 列表（如 "1,2,3"），忽略空项与非法项。
func splitIDList(s string) []int64 {
	var ids []int64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if id, err := strconv.ParseInt(part, 10, 64); err == nil && id > 0 {
			ids = append(ids, id)
		}
	}
	return ids
}

func adminVoidRedeemCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/redeem-codes", http.StatusSeeOther)
		return
	}
	// 支持单个（id）与批量（ids，逗号分隔）作废
	ids := splitIDList(r.FormValue("ids"))
	if len(ids) == 0 {
		if single, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64); err == nil {
			ids = []int64{single}
		}
	}
	if len(ids) == 0 {
		flashRedirect(w, r, redeemAdminTarget(r), "请先选择要作废的兑换码")
		return
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	res, err := models.DB.Exec("UPDATE redeem_codes SET status='void' WHERE id IN ("+ph+") AND status='active'", args...)
	if err != nil {
		http.Error(w, "操作失败，请重试", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	flashRedirect(w, r, redeemAdminTarget(r), fmt.Sprintf("已作废 %d 个兑换码", n))
}

// adminVoidOldCodesHandler voids unused codes created more than 30 days ago,
// keeping the redeem-code pool tidy.
func adminVoidOldCodesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !verifyCSRF(r) {
		http.Redirect(w, r, "/admin/redeem-codes", http.StatusSeeOther)
		return
	}
	res, err := models.DB.Exec(`UPDATE redeem_codes SET status='void'
		WHERE status='active' AND julianday(created_at) < julianday('now','-30 days')`)
	if err != nil {
		http.Error(w, "操作失败，请重试", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	flashRedirect(w, r, "/admin/redeem-codes", fmt.Sprintf("已作废 %d 个 30 天前创建且未使用的兑换码", n))
}

// generateRedeemCode 生成 32 位兑换/注册码：大写字母 + 数字（不含易混淆的
// 0/O/1/I/L），供积分兑换码与注册码共用。
func generateRedeemCode() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 32)
	bb := make([]byte, 32)
	if _, err := rand.Read(bb); err == nil {
		for i := range b {
			b[i] = chars[int(bb[i])%len(chars)]
		}
		return string(b)
	}
	// fallback (should never happen)
	now := time.Now().UnixNano()
	for i := range b {
		b[i] = chars[now%int64(len(chars))]
		now /= int64(len(chars))
	}
	return string(b)
}

// ------------------------- API Key 认证中间件 -------------------------
func apiAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")
		if strings.HasPrefix(key, "Bearer ") {
			key = strings.TrimPrefix(key, "Bearer ")
		} else {
			key = r.Header.Get("X-API-Key")
		}
		if key == "" {
			http.Error(w, `{"ok":false,"error":"missing api key"}`, http.StatusUnauthorized)
			return
		}
		hashed := models.HashAPIKey(key)
		var userID int64
		var status int
		err := models.DB.QueryRow("SELECT id, status FROM users WHERE api_key=? AND status=1", hashed).Scan(&userID, &status)
		if err != nil || status != 1 {
			http.Error(w, `{"ok":false,"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "userID", userID)
		next(w, r.WithContext(ctx))
	}
}

// ------------------------- 生成 / 刷新 API Key（网页登录 + CSRF） -------------------------
func apiKeyGenerateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !verifyCSRF(r) {
		http.Error(w, "CSRF token invalid", http.StatusBadRequest)
		return
	}
	userID, _, _ := currentUser(r)
	if userID == 0 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	key, err := models.SetAPIKey(userID)
	if err != nil {
		http.Error(w, "生成失败", http.StatusInternalServerError)
		return
	}
	sess, _ := store.Get(r, "session")
	sess.Values["new_api_key"] = key
	sess.Save(r, w)
	flashRedirect(w, r, "/profile", "新 API Key 已生成，请立即复制保存（仅显示一次）")
}

// ------------------------- 渠道列表查询 -------------------------
// GET /api/v1/channels：返回当前配置的全部生成渠道与各自的**稳定编号**
// （id 即生成接口 channel 参数的取值）。编号在渠道创建时分配并持久化，
// 不随渠道增删/调整顺序变化；index 仅为当前列表的展示顺序，请勿用作
// channel 参数。调用方凭 API Key 鉴权。
func apiChannelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"ok":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	eps := loadEndpoints()
	type chanInfo struct {
		ID          int      `json:"id"`
		Index       int      `json:"index"`
		Name        string   `json:"name"`
		NSFW        bool     `json:"nsfw"`
		Model       string   `json:"model"`
		Resolutions []string `json:"resolutions"`
		Models      []string `json:"models"`
	}
	list := []chanInfo{}
	for i, ep := range eps {
		list = append(list, chanInfo{
			ID:          ep.ID,
			Index:       i,
			Name:        ep.Name,
			NSFW:        ep.NSFW,
			Model:       ep.Model,
			Resolutions: ep.Resolutions,
			Models:      ep.Models,
		})
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"channels": list,
		"hint":     "channel 参数填写渠道编号（id 字段，字符串，从 1 开始）；编号为渠道创建时分配，不随增删/排序变化。留空自动选第一个普通渠道",
	})
}

// ------------------------- API 生成接口（积分扣减与网页一致） -------------------------
func apiGenerateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"ok":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, ok := r.Context().Value("userID").(int64)
	if !ok {
		http.Error(w, `{"ok":false,"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		Prompt      string `json:"prompt"`
		Channel     string `json:"channel"`
		N           int    `json:"n"`
		AspectRatio string `json:"aspect_ratio"`
		Resolution  string `json:"resolution"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"ok":false,"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	req.Prompt = strings.TrimSpace(req.Prompt)
	if req.Prompt == "" {
		http.Error(w, `{"ok":false,"error":"prompt required"}`, http.StatusBadRequest)
		return
	}
	if utf8.RuneCountInString(req.Prompt) > 4000 {
		http.Error(w, `{"ok":false,"error":"prompt too long"}`, http.StatusBadRequest)
		return
	}
	if req.N < 1 {
		req.N = 1
	}
	if req.N > 4 {
		req.N = 4
	}
	if req.AspectRatio == "" {
		req.AspectRatio = "1:1"
	}
	if req.Resolution == "" {
		req.Resolution = "1k"
	}
	baseCost := generationCost()
	cost := baseCost * req.N
	points := userPoints(userID)
	if int64(points) < int64(cost) {
		http.Error(w, fmt.Sprintf(`{"ok":false,"error":"积分不足，需要 %d 积分"}`, cost), http.StatusPaymentRequired)
		return
	}
	ep, err := resolveChannel(req.Channel)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"ok":false,"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}
	// 分辨率档位校验：只允许所选渠道支持的档位
	if !containsString(ep.Resolutions, req.Resolution) {
		http.Error(w, fmt.Sprintf(`{"ok":false,"error":"所选渠道不支持 %s 分辨率，支持：%s"}`, req.Resolution, strings.Join(ep.Resolutions, ", ")), http.StatusBadRequest)
		return
	}
	nsfwFlag := 0
	if ep.NSFW {
		nsfwFlag = 1
	}
	res, err := models.DB.Exec("UPDATE users SET points = points - ? WHERE id=? AND points >= ?", cost, userID, cost)
	if err != nil {
		http.Error(w, `{"ok":false,"error":"系统繁忙"}`, http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, `{"ok":false,"error":"积分不足，请稍后重试"}`, http.StatusPaymentRequired)
		return
	}
	chanModel := strings.TrimSpace(ep.Model)
	if chanModel == "" {
		chanModel = models.GetConfigOr("generation_model", "grok-imagine-image-lite")
	}
	res, err = models.DB.Exec("INSERT INTO generation_records(user_id, prompt, model, n, aspect_ratio, resolution, response_format, cost_points, status, nsfw, channel) VALUES(?,?,?,?,?,?,?,?,'processing',?,?)",
		userID, req.Prompt, chanModel, req.N, req.AspectRatio, req.Resolution, "url", cost, nsfwFlag, ep.Name)
	if err != nil {
		models.DB.Exec("UPDATE users SET points = points + ? WHERE id=?", cost, userID)
		logPoints(userID, int64(cost), "生成任务创建失败，积分退回")
		http.Error(w, `{"ok":false,"error":"任务创建失败，积分已退回"}`, http.StatusInternalServerError)
		return
	}
	rid, _ := res.LastInsertId()
	logPoints(userID, -int64(cost), "AI 图片创作消耗")
	var apiUser string
	models.DB.QueryRow("SELECT username FROM users WHERE id=?", userID).Scan(&apiUser)
	systemLog(r, userID, apiUser, "api", fmt.Sprintf("API 生成 %d 张（%s），任务 #%d", req.N, chanModel, rid), -int64(cost))
	taskQueue <- genTask{recordID: rid}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"task_id": rid,
		"message": "任务已提交",
	})
}

// ------------------------- API 状态查询 -------------------------
func apiStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"ok":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, ok := r.Context().Value("userID").(int64)
	if !ok {
		http.Error(w, `{"ok":false,"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		http.Error(w, `{"ok":false,"error":"task_id required"}`, http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil {
		http.Error(w, `{"ok":false,"error":"invalid task_id"}`, http.StatusBadRequest)
		return
	}
	var recordID int64
	var prompt, statusStr, imageURL, errorMsg string
	var n int
	var createdAt time.Time
	err = models.DB.QueryRow("SELECT id, prompt, status, image_url, error_msg, n, created_at FROM generation_records WHERE id=? AND user_id=?", id, userID).Scan(&recordID, &prompt, &statusStr, &imageURL, &errorMsg, &n, &createdAt)
	if err != nil {
		http.Error(w, `{"ok":false,"error":"task not found"}`, http.StatusNotFound)
		return
	}
	var images []string
	if statusStr == "success" {
		rows, _ := models.DB.Query("SELECT path, storage_path FROM generation_images WHERE record_id=? ORDER BY idx", id)
		defer rows.Close()
		for rows.Next() {
			var p, sp string
			if rows.Scan(&p, &sp) == nil {
				if p != "" {
					images = append(images, p)
				} else if sp != "" {
					// 本地文件已清理但有外部存储备份：以备用地址返回，
					// 与 Web 端 records 页的回退行为保持一致。
					images = append(images, sp)
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":         true,
		"task_id":    recordID,
		"status":     statusStr,
		"prompt":     prompt,
		"images":     images,
		"error":      errorMsg,
		"created_at": createdAt.Format(time.RFC3339),
	})
}

// ------------------------- API 文档页 -------------------------
func apiDocsHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, "layout.html", map[string]interface{}{
		"Title":   "API 文档",
		"Content": "content-api-docs",
	})
}
