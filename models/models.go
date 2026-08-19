package models

import (
	"database/sql"
	"time"
)

type User struct {
	ID            int64     `json:"id"`
	Username      string    `json:"username"`
	PasswordHash  string    `json:"-"`
	Email         string    `json:"email"`
	OAuthProvider string    `json:"oauth_provider"`
	OAuthID       string    `json:"oauth_id"`
	OAuthUsername string    `json:"oauth_username"`
	Points        int64     `json:"points"`
	Role          string    `json:"role"`   // user / admin
	Status        int       `json:"status"` // 1 normal, 0 disabled, -1 banned
	CreatedAt     time.Time `json:"created_at"`
}

type GenerationRecord struct {
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id"`
	Prompt      string    `json:"prompt"`
	Model       string    `json:"model"`
	N           int       `json:"n"`
	AspectRatio string    `json:"aspect_ratio"`
	Resolution  string    `json:"resolution"`
	ImageURL    string    `json:"image_url"`
	Base64Data  string    `json:"b64_json,omitempty"`
	CostPoints  int       `json:"cost_points"`
	Status      string    `json:"status"` // processing / success / failed（异步任务状态）
	CreatedAt   time.Time `json:"created_at"`
}

type RedeemCode struct {
	ID        int64         `json:"id"`
	Code      string        `json:"code"`
	Points    int64         `json:"points"`
	UsedBy    sql.NullInt64 `json:"used_by"`
	UsedAt    sql.NullTime  `json:"used_at"`
	CreatedBy int64         `json:"created_by"`
	CreatedAt time.Time     `json:"created_at"`
	Status    string        `json:"status"` // active / used
}

type CheckinLog struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Date      string    `json:"date"` // YYYY-MM-DD
	Points    int64     `json:"points"`
	CreatedAt time.Time `json:"created_at"`
}

type Config struct {
	ID    int64  `json:"id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}
