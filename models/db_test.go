package models

import (
	"path/filepath"
	"testing"
)

func TestDefaultConfigsIncludeStorageRegion(t *testing.T) {
	v, ok := defaultConfigs["storage_region"]
	if !ok {
		t.Fatal("defaultConfigs 缺少 storage_region 键（S3 签名修复的必要配置）")
	}
	if v != "us-east-1" {
		t.Errorf("storage_region 默认值 = %q, want us-east-1", v)
	}
	// 旧库升级场景：defaultConfigs 必须包含全部存储键
	for _, k := range []string{"storage_type", "storage_endpoint", "storage_bucket", "storage_region", "storage_username", "storage_password", "storage_path_prefix"} {
		if _, exists := defaultConfigs[k]; !exists {
			t.Errorf("defaultConfigs 缺少存储配置键 %s", k)
		}
	}
}

func TestSeedAndResetConfigsWithRegion(t *testing.T) {
	dir := t.TempDir()
	if err := InitDB(filepath.Join(dir, "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { DB.Close() })

	v, err := GetConfig("storage_region")
	if err != nil {
		t.Fatalf("seed 后 storage_region 读取失败: %v", err)
	}
	if v != "us-east-1" {
		t.Errorf("seed 后 storage_region = %q, want us-east-1", v)
	}

	// 模拟管理员修改后执行"恢复默认"
	if err := SetConfig("storage_region", "ap-northeast-1"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if err := SetConfig("storage_type", "s3"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if err := ResetConfigs(); err != nil {
		t.Fatalf("ResetConfigs: %v", err)
	}
	v, _ = GetConfig("storage_region")
	if v != "us-east-1" {
		t.Errorf("reset 后 storage_region = %q, want us-east-1", v)
	}
	v, _ = GetConfig("storage_type")
	if v != "" {
		t.Errorf("reset 后 storage_type = %q, want 空（未启用）", v)
	}
}