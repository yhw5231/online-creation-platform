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

func NewUploader(cfg StorageConfig) Uploader {
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 60 * time.Second
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

// S3Uploader uploads objects to an S3-compatible endpoint using AWS SigV4.
type S3Uploader struct {
	cfg StorageConfig
}

func (u *S3Uploader) Upload(localPath, key string) (UploadResult, error) {
	bucket := strings.Trim(u.cfg.Bucket, "/")
	if bucket == "" {
		return UploadResult{}, fmt.Errorf("s3 bucket 未配置")
	}
	key = strings.TrimLeft(key, "/")
	host := strings.TrimPrefix(u.cfg.baseURL(), "https://")
	host = strings.TrimPrefix(host, "http://")

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
	payloadHash := sha256Hex(body)
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// S3 path-style addressing: endpoint/bucket/key
	object := "/" + bucket + "/" + key
	canonicalURI := object
	canonicalQuery := ""
	const nl = "\n"
	canonicalHeaders := "content-type:" + contentType + nl + "host:" + host + nl +
		"x-amz-content-sha256:" + payloadHash + nl + "x-amz-date:" + amzDate + nl
	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{
		"PUT", canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
	}, nl)

	scope := dateStamp + "/" + u.cfg.Bucket + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest)),
	}, nl)

	signingKey := hmacSHA256([]byte("AWS4"+u.cfg.Password), []byte(dateStamp))
	signingKey = hmacSHA256(signingKey, []byte(u.cfg.Bucket))
	signingKey = hmacSHA256(signingKey, []byte("s3"))
	signingKey = hmacSHA256(signingKey, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	auth := "AWS4-HMAC-SHA256 Credential=" + u.cfg.Username + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	req, err := http.NewRequest(http.MethodPut, joinURL(u.cfg.baseURL(), strings.TrimLeft(object, "/")), bytes.NewReader(body))
	if err != nil {
		return UploadResult{}, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("Authorization", auth)
	req.Host = host

	client := &http.Client{Timeout: u.cfg.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return UploadResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return UploadResult{}, fmt.Errorf("s3 upload %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	pub := joinURL(u.cfg.baseURL(), strings.TrimLeft(object, "/"))
	return UploadResult{URL: pub, Ref: object}, nil
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
