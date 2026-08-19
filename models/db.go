package models

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB(dbPath string) error {
	if dbPath == "" {
		dbPath = "data/creation.db"
	}
	// WAL 提升读写并发，busy_timeout 避免高并发下的 “database is locked”
	dsn := "file:" + dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	DB = db
	if err := migrate(); err != nil {
		return err
	}
	return nil
}

func migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT DEFAULT '',
			oauth_provider TEXT DEFAULT '',
			oauth_id TEXT DEFAULT '',
			oauth_username TEXT DEFAULT '',
			points INTEGER DEFAULT 0,
			role TEXT DEFAULT 'user',
			status INTEGER DEFAULT 1,
			api_key TEXT DEFAULT '',
			last_read_notice_id INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS generation_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			prompt TEXT NOT NULL,
			model TEXT DEFAULT '',
			n INTEGER DEFAULT 1,
			aspect_ratio TEXT DEFAULT '',
			resolution TEXT DEFAULT '',
			image_url TEXT DEFAULT '',
			b64_json TEXT DEFAULT '',
			cost_points INTEGER DEFAULT 0,
			status TEXT DEFAULT 'success',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			response_format TEXT DEFAULT 'url',
			nsfw INTEGER DEFAULT 0,
			error_msg TEXT DEFAULT '',
			channel TEXT DEFAULT '',
			task_key TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS redeem_codes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			code TEXT NOT NULL UNIQUE,
			points INTEGER DEFAULT 0,
			used_by INTEGER NOT NULL DEFAULT 0,
			used_at DATETIME,
			created_by INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			status TEXT DEFAULT 'active',
			kind TEXT DEFAULT '',
			remark TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS checkin_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			date TEXT NOT NULL,
			points INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, date)
		)`,
		`CREATE TABLE IF NOT EXISTS points_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			delta INTEGER NOT NULL DEFAULT 0,
			balance INTEGER NOT NULL DEFAULT 0,
			description TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS generation_images (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			record_id INTEGER NOT NULL,
			idx INTEGER DEFAULT 0,
			path TEXT DEFAULT '',
			storage_type TEXT DEFAULT '',
			storage_path TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT DEFAULT '',
			key_hash TEXT NOT NULL DEFAULT '',
			channel_id INTEGER DEFAULT 0,
			status INTEGER DEFAULT 1,
			last_used_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT DEFAULT '',
			key_hash TEXT NOT NULL DEFAULT '',
			channel_id INTEGER DEFAULT 0,
			status INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)`,
		`CREATE TABLE IF NOT EXISTS configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT NOT NULL UNIQUE,
			value TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS notices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL DEFAULT '',
			content TEXT NOT NULL DEFAULT '',
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS system_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL DEFAULT 0,
			username TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '',
			points_delta INTEGER NOT NULL DEFAULT 0,
			ip TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_system_logs_created ON system_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_system_logs_user ON system_logs(username)`,
		`CREATE INDEX IF NOT EXISTS idx_system_logs_action ON system_logs(action)`,
		`CREATE INDEX IF NOT EXISTS idx_system_logs_ip ON system_logs(ip)`,
	}
	for _, s := range stmts {
		if _, err := DB.Exec(s); err != nil {
			return err
		}
	}
	if err := ensureColumns(); err != nil {
		return err
	}
	if err := backfillTaskKeys(); err != nil {
		return err
	}
	if err := seedConfigs(); err != nil {
		return err
	}
	if err := seedAdmin(); err != nil {
		return err
	}
	return nil
}

// ensureColumns adds columns introduced by later versions to tables created
// by older builds, so upgrading an existing database never errors on a
// missing column. It is idempotent: existing columns are left untouched.
func ensureColumns() error {
	// 仅在此登记历史迭代新增的列；新列务必同时加入上方 CREATE TABLE
	adds := []string{
		"ALTER TABLE generation_records ADD COLUMN resolution TEXT DEFAULT ''",
		"ALTER TABLE generation_records ADD COLUMN n INTEGER DEFAULT 1",
		"ALTER TABLE generation_records ADD COLUMN image_url TEXT DEFAULT ''",
		"ALTER TABLE generation_records ADD COLUMN status TEXT DEFAULT 'success'",
		"ALTER TABLE generation_records ADD COLUMN response_format TEXT DEFAULT 'url'",
		"ALTER TABLE generation_records ADD COLUMN nsfw INTEGER DEFAULT 0",
		"ALTER TABLE generation_records ADD COLUMN error_msg TEXT DEFAULT ''",
		"ALTER TABLE generation_records ADD COLUMN channel TEXT DEFAULT ''",
		"ALTER TABLE users ADD COLUMN api_key TEXT DEFAULT ''",
		"ALTER TABLE users ADD COLUMN oauth_username TEXT DEFAULT ''",
		"ALTER TABLE generation_images ADD COLUMN storage_type TEXT DEFAULT ''",
		"ALTER TABLE generation_images ADD COLUMN storage_path TEXT DEFAULT ''",
		// redeem_codes.kind：'' = 旧版通用码（兑换/注册都可用）；'points' = 积分兑换码；'register' = 注册码
		"ALTER TABLE redeem_codes ADD COLUMN kind TEXT DEFAULT ''",
		// redeem_codes.remark：管理员为该码填写的备注（区分用途/来源）
		"ALTER TABLE redeem_codes ADD COLUMN remark TEXT DEFAULT ''",
		// users.last_read_notice_id：用户已读公告推进到的最新公告 id，用于导航红点
		"ALTER TABLE users ADD COLUMN last_read_notice_id INTEGER NOT NULL DEFAULT 0",
		// generation_records.task_key：每条创作记录的随机任务编号（8 位小写字母数字），
		// 代替递增的 id 对外展示，避免用户看到顺序 ID。
		"ALTER TABLE generation_records ADD COLUMN task_key TEXT DEFAULT ''",
	}
	for _, ddl := range adds {
		if _, err := DB.Exec(ddl); err != nil {
			// 列已存在是唯一允许的失败（幂等）
			if !strings.Contains(err.Error(), "duplicate column") {
				return err
			}
		}
	}
	return nil
}

var defaultConfigs = map[string]string{
	"site_name":                      "在线创作平台",
	"open_registration":              "true",
	"enable_password_registration":   "true",
	"enable_thirdparty_registration": "true",
	"require_reg_code":               "false",
	"initial_points":                 "0",
	"enable_daily_checkin":           "true",
	"checkin_mode":                   "fixed", // fixed / random
	"checkin_fixed_points":           "10",
	"checkin_random_min":             "1",
	"checkin_random_max":             "20",
	"enable_thirdparty_login":        "false",
	"linuxdo_client_id":              "",
	"linuxdo_client_secret":          "",
	"linuxdo_redirect_uri":           "",
	"generation_api_url":             "",
	"generation_api_key":             "",
	"generation_model":               "grok-imagine-image-lite",
	"generation_endpoints":           "",
	"generation_cost_points":         "10",
	"storage_type":                   "", // none / s3 / webdav / post
	"storage_endpoint":               "",
	"storage_bucket":                 "",
	"storage_region":                 "us-east-1",
	"storage_username":               "",
	"storage_password":               "",
	"storage_path_prefix":            "",
	"cleanup_enabled":                "false",
	"cleanup_keep_days":              "30",
	"cleanup_max_mb":                 "2048",
}

func seedConfigs() error {
	for k, v := range defaultConfigs {
		var cnt int
		err := DB.QueryRow("SELECT COUNT(*) FROM configs WHERE key=?", k).Scan(&cnt)
		if err != nil {
			return err
		}
		if cnt == 0 {
			_, err := DB.Exec("INSERT INTO configs(key, value) VALUES(?,?)", k, v)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// ResetConfigs restores every known config key to its default value (upsert),
// used by the admin “恢复默认设置” action.
func ResetConfigs() error {
	for k, v := range defaultConfigs {
		_, err := DB.Exec(`INSERT INTO configs(key, value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func seedAdmin() error {
	var cnt int
	if err := DB.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin'").Scan(&cnt); err != nil {
		return err
	}
	if cnt > 0 {
		return nil
	}
	log.Println("No admin user found. Creating default admin (admin/admin123)")
	hash, err := HashPassword("admin123")
	if err != nil {
		return err
	}
	_, err = DB.Exec(
		"INSERT INTO users(username, password_hash, points, role, status) VALUES(?,?,?,?,?)",
		"admin", hash, 0, "admin", 1,
	)
	return err
}

// GenerateAPIKey 生成一个新的随机 API Key（192 位熵，格式 sk-xxxx），
// 每次生成都不同，用于外部程序调用本站生成接口。
func GenerateAPIKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sk-" + hex.EncodeToString(b), nil
}

// HashAPIKey 返回 API Key 的 SHA-256 十六进制摘要。数据库中只保存摘要，
// 即使数据泄露也无法反推或直接使用用户的 Key。
func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// CreateAPIKey 为用户创建一条新的 API Key：name 用于区分用途，
// channelID 绑定该 Key 固定使用的渠道编号（0 表示不绑定、
// 调用时自动选普通渠道）。返回明文 Key 供页面一次性展示。
func CreateAPIKey(userID int64, name string, channelID int) (string, error) {
	key, err := GenerateAPIKey()
	if err != nil {
		return "", err
	}
	if _, err := DB.Exec("INSERT INTO api_keys(user_id, name, key_hash, channel_id) VALUES(?,?,?,?)",
		userID, name, HashAPIKey(key), channelID); err != nil {
		return "", err
	}
	return key, nil
}

// ListAPIKeys 返回用户全部 API Key 的展示信息（不含明文）。
func ListAPIKeys(userID int64) []map[string]interface{} {
	keys := []map[string]interface{}{}
	rows, err := DB.Query("SELECT id, name, key_hash, channel_id, status, created_at FROM api_keys WHERE user_id=? ORDER BY id DESC", userID)
	if err != nil {
		return keys
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name, hash, createdAt string
		var channelID, status int
		if rows.Scan(&id, &name, &hash, &channelID, &status, &createdAt) == nil {
			mask := ""
			if len(hash) >= 8 {
				mask = hash[:8] + "****"
			} else if hash != "" {
				mask = "****"
			}
			keys = append(keys, map[string]interface{}{
				"ID":        id,
				"Name":      name,
				"Mask":      mask,
				"ChannelID": channelID,
				"Status":    status,
				"CreatedAt": createdAt,
			})
		}
	}
	return keys
}

// DeleteAPIKey 删除用户的一条 API Key（仅限本人）。
func DeleteAPIKey(userID, keyID int64) error {
	_, err := DB.Exec("DELETE FROM api_keys WHERE id=? AND user_id=?", keyID, userID)
	return err
}

// FindAPIKeyUser 按 Key 哈希查找使用该 Key 的用户与绑定渠道编号。
// 返回 userID；未找到时 userID 为 0。channelID 为该 Key 创建时绑定的
// 渠道编号（0 = 未绑定，调用时自动选普通渠道）。
func FindAPIKeyUser(keyHash string) (userID int64, channelID int) {
	DB.QueryRow("SELECT user_id, channel_id FROM api_keys WHERE key_hash=? AND status=1", keyHash).Scan(&userID, &channelID)
	return
}

// SetAPIKey 为用户设置新的 API Key（保存哈希），返回明文 Key 供页面一次性展示。
// 兼容旧版单 Key 方式：不写 api_keys 表（新用户请使用 CreateAPIKey）。
func SetAPIKey(userID int64) (string, error) {
	key, err := GenerateAPIKey()
	if err != nil {
		return "", err
	}
	if _, err := DB.Exec("UPDATE users SET api_key=? WHERE id=?", HashAPIKey(key), userID); err != nil {
		return "", err
	}
	return key, nil
}

// GetAPIKeyHash 返回用户当前的 API Key 哈希（为空表示未生成）。
// 兼容旧版单 Key：仅查 users.api_key。
func GetAPIKeyHash(userID int64) string {
	var h string
	DB.QueryRow("SELECT api_key FROM users WHERE id=?", userID).Scan(&h)
	return h
}

// RandomTaskKey 生成一个 8 位小写字母数字随机串（a-z0-9，如 "d5ey63d7"），
// 用作创作记录的对外任务编号，避免暴露递增的数据库 ID。
func RandomTaskKey() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// 兜底：用时间戳派生，保证非空
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = alphabet[int(now)%len(alphabet)]
			now /= int64(len(alphabet))
		}
		return string(b)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// backfillTaskKeys 为历史数据中缺失 task_key 的记录补发随机编号
// （幂等：只填充空值，重启可安全重跑）。
func backfillTaskKeys() error {
	rows, err := DB.Query("SELECT id FROM generation_records WHERE task_key IS NULL OR task_key = ''")
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := DB.Exec("UPDATE generation_records SET task_key=? WHERE id=?", RandomTaskKey(), id); err != nil {
			return err
		}
	}
	return nil
}
