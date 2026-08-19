package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

type GenRequest struct {
	Model          string `json:"model"`
	Prompt         string `json:"prompt"`
	N              int    `json:"n"`
	AspectRatio    string `json:"aspect_ratio,omitempty"`
	Resolution     string `json:"resolution,omitempty"`
	ResponseFormat string `json:"response_format,omitempty"`
	Stream         bool   `json:"stream,omitempty"`
}

type GenResult struct {
	URL    string `json:"url"`
	B64    string `json:"b64_json"`
}

type GenResponse struct {
	Created int64       `json:"created"`
	Data    []GenResult `json:"data"`
}

type GrokClient struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func NewGrokClient(baseURL, apiKey string) *GrokClient {
	if baseURL == "" {
		baseURL = "https://grok.7890456.xyz/v1"
	}
	return &GrokClient{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP: &http.Client{Timeout: 3 * time.Minute},
	}
}

// Generate calls /images/generations per docs/grok-image-api.md
func (c *GrokClient) Generate(req GenRequest) (*GenResponse, error) {
	endpoint := c.BaseURL + "/images/generations"
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// 限制响应体积，避免上游异常时无界读取打满内存
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// 504/502 属于网关或上游服务问题：把原始 HTML/JSON 报文换成用户
		// 可读的提示，避免把 openresty 超时页等原始内容直接暴露给用户。
		// 504：网关超时，通常意味着生成内容被网关拦截（审查/拦截超时）。
		if resp.StatusCode == http.StatusGatewayTimeout {
			return nil, fmt.Errorf("生成的内容可能被网关拦截（上游请求超时），请调整提示词或稍后重试")
		}
		// 502：上游服务暂不可用，或提示词未通过上游审核被拒。
		if resp.StatusCode == http.StatusBadGateway {
			return nil, fmt.Errorf("上游服务暂不可用或提示词未通过上游审核，请稍后重试或调整提示词")
		}
		note := strings.TrimSpace(string(data))
		if utf8.RuneCountInString(note) > 300 {
			note = string([]rune(note)[:300]) + "…（已截断）"
		}
		return nil, fmt.Errorf("grok api error %d: %s", resp.StatusCode, note)
	}
	var gen GenResponse
	if err := json.Unmarshal(data, &gen); err != nil {
		snippet := strings.TrimSpace(string(data))
		if utf8.RuneCountInString(snippet) > 200 {
			snippet = string([]rune(snippet)[:200]) + "…"
		}
		return nil, fmt.Errorf("parse response: %v (%s)", err, snippet)
	}
	// 直接把"空响应"拒之门外，主调方无需再分情况处理
	if len(gen.Data) == 0 {
		return nil, fmt.Errorf("empty image response")
	}
	return &gen, nil
}

// DownloadFromURL fetches bytes of a generated image URL.
func (c *GrokClient) DownloadFromURL(url string) ([]byte, error) {
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download status %d", resp.StatusCode)
	}
	// 限制下载体积，避免上游异常时读爆内存（与服务端响应限制 64MB 对齐）
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

// SaveImage writes bytes to a file under the given dir.
func SaveImage(dir string, data []byte, ext string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := dir + "/" + fmt.Sprintf("%d_%s.%s", time.Now().UnixNano(), randomHex(8), ext)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func randomHex(n int) string {
	const letters = "0123456789abcdef"
	b := make([]byte, n)
	now := time.Now().UnixNano()
	for i := range b {
		b[i] = letters[now%int64(len(letters))]
		now /= int64(len(letters))
	}
	return string(b)
}