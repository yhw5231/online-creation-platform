package models

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log"
	"strings"

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
			points INTEGER DEFAULT 0,
			role TEXT DEFAULT 'user',
			status INTEGER DEFAULT 1,
			api_key TEXT DEFAULT '',
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
			channel TEXT DEFAULT ''
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
			kind TEXT DEFAULT ''
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
	}
	for _, s := range stmts {
		if _, err := DB.Exec(s); err != nil {
			return err
		}
	}
	if err := ensureColumns(); err != nil {
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
		"ALTER TABLE generation_images ADD COLUMN storage_type TEXT DEFAULT ''",
		"ALTER TABLE generation_images ADD COLUMN storage_path TEXT DEFAULT ''",
		// redeem_codes.kind：'' = 旧版通用码（兑换/注册都可用）；'points' = 积分兑换码；'register' = 注册码
		"ALTER TABLE redeem_codes ADD COLUMN kind TEXT DEFAULT ''",
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

// SetAPIKey 为用户设置新的 API Key（保存哈希），返回明文 Key 供页面一次性展示。
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
func GetAPIKeyHash(userID int64) string {
	var h string
	DB.QueryRow("SELECT api_key FROM users WHERE id=?", userID).Scan(&h)
	return h
}
