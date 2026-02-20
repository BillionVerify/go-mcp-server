package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// APIClient 封装对外部 API 的调用
type APIClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *logrus.Logger
}

// NewAPIClient 创建 API 客户端
func NewAPIClient(baseURL string, logger *logrus.Logger) *APIClient {
	return &APIClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: logger,
	}
}

// APIResponse 通用 API 响应结构
type APIResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   *APIError       `json:"error,omitempty"`
}

// APIError API 错误结构
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// doRequest 执行 HTTP 请求
func (c *APIClient) doRequest(method, path string, apiKey string, body interface{}) (*APIResponse, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonData)
	}

	url := c.baseURL + path
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("BV-API-KEY", apiKey)

	c.logger.Debugf("API Request: %s %s", method, path)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	c.logger.Debugf("API Response: status=%d, body=%s", resp.StatusCode, string(respBody))

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		// 如果无法解析为标准格式，尝试直接返回原始数据
		return &APIResponse{
			Success: resp.StatusCode >= 200 && resp.StatusCode < 300,
			Data:    respBody,
		}, nil
	}

	// 检查 HTTP 状态码
	if resp.StatusCode >= 400 {
		if apiResp.Error != nil {
			return nil, fmt.Errorf("%s: %s", apiResp.Error.Code, apiResp.Error.Message)
		}
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	return &apiResp, nil
}

// VerifySingleEmail 验证单个邮箱
func (c *APIClient) VerifySingleEmail(apiKey, email string, checkSMTP, forceRefresh bool) (map[string]interface{}, error) {
	body := map[string]interface{}{
		"email":         email,
		"check_smtp":    checkSMTP,
		"force_refresh": forceRefresh,
	}

	resp, err := c.doRequest("POST", "/v1/verify", apiKey, body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// VerifyBatchEmails 批量验证邮箱
func (c *APIClient) VerifyBatchEmails(apiKey string, emails []string, checkSMTP bool) (map[string]interface{}, error) {
	body := map[string]interface{}{
		"emails":     emails,
		"check_smtp": checkSMTP,
	}

	resp, err := c.doRequest("POST", "/v1/batch", apiKey, body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetAccountBalance 获取账户余额
func (c *APIClient) GetAccountBalance(apiKey string) (map[string]interface{}, error) {
	resp, err := c.doRequest("GET", "/v1/balance", apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetTaskStatus 获取任务状态
func (c *APIClient) GetTaskStatus(apiKey, taskID string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/v1/status/%s", taskID)
	resp, err := c.doRequest("GET", path, apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetVerificationHistory 获取验证历史
func (c *APIClient) GetVerificationHistory(apiKey string, page, limit int) (map[string]interface{}, error) {
	path := fmt.Sprintf("/v1/history?page=%d&limit=%d", page, limit)
	resp, err := c.doRequest("GET", path, apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetVerificationStats 获取验证统计
func (c *APIClient) GetVerificationStats(apiKey, period string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/v1/stats?period=%s", period)
	resp, err := c.doRequest("GET", path, apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetDownloadURL 获取文件验证结果下载 URL
func (c *APIClient) GetDownloadURL(apiKey, jobID string, filters map[string]bool) (map[string]interface{}, error) {
	// 构建查询参数
	path := fmt.Sprintf("/v1/download/%s", jobID)
	queryParams := ""
	for key, value := range filters {
		if value {
			if queryParams == "" {
				queryParams = "?"
			} else {
				queryParams += "&"
			}
			queryParams += key + "=true"
		}
	}
	path += queryParams

	resp, err := c.doRequest("GET", path, apiKey, nil)
	if err != nil {
		return nil, err
	}

	// 如果是重定向响应，返回下载 URL
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		// 可能是直接返回的 URL 或其他格式
		return map[string]interface{}{
			"download_url": c.baseURL + path,
			"message":      "Use this URL with your API key header to download results",
		}, nil
	}

	return result, nil
}

// CreateWebhook 创建 Webhook
func (c *APIClient) CreateWebhook(apiKey, url string, events []string) (map[string]interface{}, error) {
	body := map[string]interface{}{
		"url":    url,
		"events": events,
	}

	resp, err := c.doRequest("POST", "/v1/webhooks", apiKey, body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// ListWebhooks 列出所有 Webhook
func (c *APIClient) ListWebhooks(apiKey string) (map[string]interface{}, error) {
	resp, err := c.doRequest("GET", "/v1/webhooks", apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// DeleteWebhook 删除 Webhook
func (c *APIClient) DeleteWebhook(apiKey, webhookID string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/v1/webhooks/%s", webhookID)
	resp, err := c.doRequest("DELETE", path, apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		// DELETE 可能返回空响应
		return map[string]interface{}{
			"success": true,
			"message": "Webhook deleted successfully",
		}, nil
	}

	return result, nil
}
