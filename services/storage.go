package services

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// StorageConfig describes external long-term storage settings.
//   - "" / "none": no external storage, images stay local only
//   - "s3":        S3-compatible object storage (AWS/MinIO/OSS/COS)
//   - "webdav":    WebDAV server (Basic Auth)
//   - "post":      generic multipart POST upload endpoint
type StorageConfig struct {
	Type        string
	Endpoint    string
	Bucket      string
	Region      string
	Username    string
	Password    string
	PathPrefix  string
	LocalDir    string
	HTTPTimeout time.Duration
}

type UploadResult struct {
	URL string
	Ref string
}

type Uploader interface {
	Upload(localPath, key string) (UploadResult, error)
}

// RemoteDeleter is implemented by uploaders that can remove a remote object
// (S3 and WebDAV). POST-based uploads cannot delete, so callers must treat
// a missing interface (or a returned error) as best-effort.
type RemoteDeleter interface {
	Delete(ref string) error
}

func NewUploader(cfg StorageConfig) Uploader {
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 60 * time.Second
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	switch strings.ToLower(cfg.Type) {
	case "s3":
		return &S3Uploader{cfg: cfg}
	case "webdav":
		return &WebDAVUploader{cfg: cfg}
	case "post":
		return &PostUploader{cfg: cfg}
	default:
		return nil
	}
}

func (cfg StorageConfig) keyFor(filename string) string {
	prefix := strings.Trim(cfg.PathPrefix, "/")
	if prefix == "" {
		return filename
	}
	return prefix + "/" + filename
}

func (cfg StorageConfig) baseURL() string {
	return strings.TrimRight(cfg.Endpoint, "/")
}

func joinURL(base, p string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(p, "/")
}

// hostOf extracts the bare host (host[:port]) from an endpoint URL, so an
// endpoint carrying a path prefix never leaks it into the Host header.
func hostOf(endpoint string) string {
	raw := endpoint
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	}
	return u.Host
}

// escapePathSegments percent-encodes each path segment of an S3 object key
// (spaces, UTF-8, reserved chars) so the signed canonical URI always matches
// the actual request URI.
func escapePathSegments(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		if parts[i] != "" {
			parts[i] = url.PathEscape(parts[i])
		}
	}
	return strings.Join(parts, "/")
}

// S3Uploader uploads objects to an S3-compatible endpoint using AWS SigV4.
type S3Uploader struct {
	cfg StorageConfig
}

// s3Sign computes the AWS SigV4 Authorization header for the given request.
// region defaults to us-east-1 (set in NewUploader).
func (u *S3Uploader) s3Sign(method, canonicalURI, contentType, payloadHash, host, amzDate, dateStamp string) string {
	const nl = "\n"
	canonicalHeaders := ""
	if contentType != "" {
		canonicalHeaders += "content-type:" + contentType + nl
	}
	canonicalHeaders += "host:" + host + nl +
		"x-amz-content-sha256:" + payloadHash + nl + "x-amz-date:" + amzDate + nl
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	if contentType != "" {
		signedHeaders = "content-type;" + signedHeaders
	}
	canonicalRequest := strings.Join([]string{
		method, canonicalURI, "", canonicalHeaders, signedHeaders, payloadHash,
	}, nl)

	scope := dateStamp + "/" + u.cfg.Region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest)),
	}, nl)

	signingKey := hmacSHA256([]byte("AWS4"+u.cfg.Password), []byte(dateStamp))
	signingKey = hmacSHA256(signingKey, []byte(u.cfg.Region))
	signingKey = hmacSHA256(signingKey, []byte("s3"))
	signingKey = hmacSHA256(signingKey, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	return "AWS4-HMAC-SHA256 Credential=" + u.cfg.Username + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

// s3Request sends a signed request (PUT/DELETE) to endpoint/bucket/key and
// returns the server's error body on failure.
func (u *S3Uploader) s3Request(method, object string, body []byte, contentType string) error {
	host := hostOf(u.cfg.baseURL())
	payloadHash := sha256Hex(body)
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	escaped := escapePathSegments(object)
	auth := u.s3Sign(method, escaped, contentType, payloadHash, host, amzDate, dateStamp)

	req, err := http.NewRequest(method, joinURL(u.cfg.baseURL(), strings.TrimLeft(escaped, "/")), bytes.NewReader(body))
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("Authorization", auth)
	req.Host = host

	client := &http.Client{Timeout: u.cfg.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("s3 %s %d: %s", method, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// Upload PUTs a local file to bucket/key via SigV4.
func (u *S3Uploader) Upload(localPath, key string) (UploadResult, error) {
	bucket := strings.Trim(u.cfg.Bucket, "/")
	if bucket == "" {
		return UploadResult{}, fmt.Errorf("s3 bucket 未配置")
	}
	key = strings.TrimLeft(key, "/")

	file, err := os.Open(localPath)
	if err != nil {
		return UploadResult{}, err
	}
	defer file.Close()
	body, err := io.ReadAll(file)
	if err != nil {
		return UploadResult{}, err
	}

	contentType := "application/octet-stream"
	if ct := detectContentType(body); ct != "" {
		contentType = ct
	}

	// S3 path-style addressing: endpoint/bucket/key
	object := "/" + bucket + "/" + key
	if err := u.s3Request(http.MethodPut, object, body, contentType); err != nil {
		return UploadResult{}, err
	}

	escaped := escapePathSegments(object)
	pub := joinURL(u.cfg.baseURL(), strings.TrimLeft(escaped, "/"))
	return UploadResult{URL: pub, Ref: object}, nil
}

// Delete removes an object. ref may be either the object path recorded as
// Ref (/bucket/key) or the full public URL (endpoint/bucket/key as stored
// in storage_path); the URL form is parsed down to its path. 404 is treated
// as success (already gone).
func (u *S3Uploader) Delete(ref string) error {
	if ref == "" {
		return nil
	}
	object := ref
	if strings.Contains(object, "://") {
		if u2, err := url.Parse(object); err == nil {
			object = u2.Path
		}
	}
	if !strings.HasPrefix(object, "/") {
		object = "/" + object
	}
	err := u.s3Request(http.MethodDelete, object, nil, "")
	if err != nil && strings.Contains(err.Error(), "404") {
		return nil
	}
	return err
}

// WebDAVUploader PUTs files to a WebDAV server with optional Basic Auth.
type WebDAVUploader struct {
	cfg StorageConfig
}

func (u *WebDAVUploader) Upload(localPath, key string) (UploadResult, error) {
	file, err := os.Open(localPath)
	if err != nil {
		return UploadResult{}, err
	}
	defer file.Close()
	body, err := io.ReadAll(file)
	if err != nil {
		return UploadResult{}, err
	}
	contentType := "application/octet-stream"
	if ct := detectContentType(body); ct != "" {
		contentType = ct
	}
	target := joinURL(u.cfg.baseURL(), u.cfg.keyFor(key))
	req, err := http.NewRequest(http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return UploadResult{}, err
	}
	req.Header.Set("Content-Type", contentType)
	if u.cfg.Username != "" {
		req.SetBasicAuth(u.cfg.Username, u.cfg.Password)
	}
	client := &http.Client{Timeout: u.cfg.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return UploadResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return UploadResult{}, fmt.Errorf("webdav upload %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return UploadResult{URL: target, Ref: target}, nil
}

// Delete issues a WebDAV DELETE on the recorded remote URL.
// 404 is treated as success (already gone).
func (u *WebDAVUploader) Delete(ref string) error {
	if ref == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodDelete, ref, nil)
	if err != nil {
		return err
	}
	if u.cfg.Username != "" {
		req.SetBasicAuth(u.cfg.Username, u.cfg.Password)
	}
	client := &http.Client{Timeout: u.cfg.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webdav delete %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// PostUploader uploads via multipart/form-data POST to a generic endpoint.
type PostUploader struct {
	cfg StorageConfig
}

// parsePostResponse extracts a public URL from common upload API JSON shapes.
func parsePostResponse(body []byte, fallback string) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return fallback
	}
	var obj map[string]interface{}
	if json.Unmarshal(body, &obj) == nil {
		for _, k := range []string{"url", "file_url", "download_url", "path", "src", "link", "data"} {
			if v, ok := obj[k]; ok {
				switch tv := v.(type) {
				case string:
					if tv != "" {
						return tv
					}
				case map[string]interface{}:
					if s, ok := tv["url"].(string); ok && s != "" {
						return s
					}
				}
			}
		}
		if arr, ok := obj["urls"].([]interface{}); ok && len(arr) > 0 {
			if s, ok := arr[0].(string); ok && s != "" {
				return s
			}
		}
		if arr, ok := obj["data"].([]interface{}); ok && len(arr) > 0 {
			if s, ok := arr[0].(string); ok && s != "" {
				return s
			}
		}
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	return fallback
}

func (u *PostUploader) Upload(localPath, key string) (UploadResult, error) {
	endpoint := strings.TrimSpace(u.cfg.Endpoint)
	if endpoint == "" {
		return UploadResult{}, fmt.Errorf("post 上传接口地址未配置")
	}
	file, err := os.Open(localPath)
	if err != nil {
		return UploadResult{}, err
	}
	defer file.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", path.Base(key))
	if err != nil {
		return UploadResult{}, err
	}
	if _, err := io.Copy(fw, file); err != nil {
		return UploadResult{}, err
	}
	for k, v := range map[string]string{
		"path": u.cfg.PathPrefix, "key": u.cfg.keyFor(key),
	} {
		if v != "" {
			mw.WriteField(k, v)
		}
	}
	mw.Close()

	req, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		return UploadResult{}, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if u.cfg.Username != "" {
		req.SetBasicAuth(u.cfg.Username, u.cfg.Password)
	}
	client := &http.Client{Timeout: u.cfg.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return UploadResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return UploadResult{}, fmt.Errorf("post upload %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	pub := parsePostResponse(body, joinURL(u.cfg.baseURL(), u.cfg.keyFor(key)))
	return UploadResult{URL: pub, Ref: u.cfg.keyFor(key)}, nil
}

// ------------------------------- shared utils -------------------------------

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// detectContentType sniffs content type; WebP needs magic-byte detection.
func detectContentType(b []byte) string {
	if len(b) >= 12 && string(b[0:4]) == "RIFF" && string(b[8:12]) == "WEBP" {
		return "image/webp"
	}
	ct := http.DetectContentType(b)
	if ct != "application/octet-stream" {
		return ct
	}
	return ""
}
