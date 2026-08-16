package services

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestS3SignUsesRegion verifies the SigV4 scope uses the configured region
// (not the bucket) and returns an absolute public URL.
func TestS3SignUsesRegion(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	dir := t.TempDir()
	lp := filepath.Join(dir, "img.png")
	os.WriteFile(lp, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, 0o644)

	u := NewUploader(StorageConfig{
		Type: "s3", Endpoint: srv.URL, Bucket: "mybucket", Region: "ap-northeast-1",
		Username: "AKID", Password: "secret", HTTPTimeout: 5e9,
	})
	res, err := u.Upload(lp, "123.png")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	// region 应出现在 scope 中
	if !strings.Contains(auth, "/ap-northeast-1/s3/aws4_request") {
		t.Errorf("scope 应包含 region: %s", auth)
	}
	if strings.Contains(auth, "/mybucket/s3/aws4_request") {
		t.Errorf("scope 不应包含 bucket: %s", auth)
	}
	// 落库用 URL：必须完整可访问
	if !strings.HasPrefix(res.URL, srv.URL+"/mybucket/123.png") {
		t.Errorf("URL 应为完整地址: %q", res.URL)
	}
	// 默认 region
	u2 := NewUploader(StorageConfig{Type: "s3", Endpoint: srv.URL, Bucket: "b", Username: "A", Password: "s", HTTPTimeout: 5e9})
	if u2.(*S3Uploader).cfg.Region != "us-east-1" {
		t.Errorf("默认 region 应为 us-east-1, got %q", u2.(*S3Uploader).cfg.Region)
	}
}

// TestS3DeleteSupportsFullURL verifies Delete accepts the full public URL
// stored in storage_path and issues it against the object path.
func TestS3DeleteSupportsFullURL(t *testing.T) {
	var method, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		w.WriteHeader(204)
	}))
	defer srv.Close()

	u := NewUploader(StorageConfig{Type: "s3", Endpoint: srv.URL, Bucket: "b", Username: "A", Password: "s", HTTPTimeout: 5e9})
	if err := u.(*S3Uploader).Delete(srv.URL + "/b/x/123.png"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if method != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", method)
	}
	if path != "/b/x/123.png" {
		t.Errorf("path = %q, want /b/x/123.png", path)
	}
	// 对象路径形式（Ref）也应可用
	if err := u.(*S3Uploader).Delete("/b/456.png"); err != nil {
		t.Fatalf("delete by ref: %v", err)
	}
	if path != "/b/456.png" {
		t.Errorf("path = %q, want /b/456.png", path)
	}
}

// TestS3Delete404IsOK verifies 404 on delete is treated as success.
func TestS3Delete404IsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	u := NewUploader(StorageConfig{Type: "s3", Endpoint: srv.URL, Bucket: "b", Username: "A", Password: "s", HTTPTimeout: 5e9})
	if err := u.(*S3Uploader).Delete("/b/gone.png"); err != nil {
		t.Errorf("404 delete should be OK, got %v", err)
	}
}

// TestWebDAVDelete verifies remote deletion for WebDAV.
func TestWebDAVDelete(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(204)
			return
		}
		got = r.URL.Path
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
	}))
	defer srv.Close()

	dir := t.TempDir()
	lp := filepath.Join(dir, "img.png")
	os.WriteFile(lp, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, 0o644)

	u := NewUploader(StorageConfig{Type: "webdav", Endpoint: srv.URL, PathPrefix: "imgs", HTTPTimeout: 5e9})
	res, err := u.Upload(lp, "a.png")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !strings.HasPrefix(res.URL, srv.URL) {
		t.Errorf("webdav URL should be absolute: %q", res.URL)
	}
	if got != "/imgs/a.png" {
		t.Errorf("webdav path = %q, want /imgs/a.png", got)
	}
	if err := u.(*WebDAVUploader).Delete(res.URL); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// TestHostOfWithPathPrefix ensures Host header never contains a path suffix.
func TestHostOfWithPathPrefix(t *testing.T) {
	if got := hostOf("https://oss.example.com/api/v1"); got != "oss.example.com" {
		t.Errorf("hostOf = %q, want oss.example.com", got)
	}
	if got := hostOf("http://127.0.0.1:9000"); got != "127.0.0.1:9000" {
		t.Errorf("hostOf = %q", got)
	}
	if got := hostOf("oss.example.com"); got != "oss.example.com" {
		t.Errorf("hostOf no-scheme = %q", got)
	}
}

// TestEscapePathSegments ensures reserved chars in keys are encoded.
func TestEscapePathSegments(t *testing.T) {
	if got := escapePathSegments("/b/a b/图.png"); got != "/b/a%20b/%E5%9B%BE.png" {
		t.Errorf("escapePathSegments = %q", got)
	}
}

// TestInterfaceSatisfaction guards RemoteDeleter implementers.
func TestInterfaceSatisfaction(t *testing.T) {
	var _ RemoteDeleter = (*S3Uploader)(nil)
	var _ RemoteDeleter = (*WebDAVUploader)(nil)
}
