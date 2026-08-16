package models

import "golang.org/x/crypto/bcrypt"

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func GetConfigOr(key, def string) string {
	if v, err := GetConfig(key); err == nil && v != "" {
		return v
	}
	return def
}

func GetConfig(key string) (string, error) {
	var v string
	err := DB.QueryRow("SELECT value FROM configs WHERE key=?", key).Scan(&v)
	return v, err
}

func SetConfig(key, value string) error {
	_, err := DB.Exec("INSERT INTO configs(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
	return err
}

func GetAllConfigs() (map[string]string, error) {
	rows, err := DB.Query("SELECT key, value FROM configs")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, rows.Err()
}