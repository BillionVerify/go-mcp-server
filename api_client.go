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

// APIClient wraps BillionVerify API calls.
type APIClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *logrus.Logger
}

// NewAPIClient creates a new API client.
func NewAPIClient(baseURL string, logger *logrus.Logger) *APIClient {
	return &APIClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: logger,
	}
}

// APIResponse is the standard API response envelope.
type APIResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   *APIError       `json:"error,omitempty"`
}

// APIError represents an API error.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// doRequest executes an authenticated HTTP request.
func (c *APIClient) doRequest(method, path string, apiKey string, body interface{}) (*APIResponse, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("BV-API-KEY", apiKey)

	c.logger.Debugf("API request: %s %s", method, path)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	c.logger.Debugf("API response: status=%d", resp.StatusCode)

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		// If not standard JSON, return raw response
		return &APIResponse{
			Success: resp.StatusCode >= 200 && resp.StatusCode < 300,
			Data:    respBody,
		}, nil
	}

	if resp.StatusCode >= 400 {
		if apiResp.Error != nil {
			return nil, fmt.Errorf("%s: %s", apiResp.Error.Code, apiResp.Error.Message)
		}
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	return &apiResp, nil
}

// VerifySingleEmail verifies a single email address.
func (c *APIClient) VerifySingleEmail(apiKey, email string, checkSMTP, forceRefresh bool) (map[string]interface{}, error) {
	resp, err := c.doRequest("POST", "/v1/verify/single", apiKey, map[string]interface{}{
		"email":         email,
		"check_smtp":    checkSMTP,
		"force_refresh": forceRefresh,
	})
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// VerifyBatchEmails verifies multiple email addresses.
func (c *APIClient) VerifyBatchEmails(apiKey string, emails []string, checkSMTP bool) (map[string]interface{}, error) {
	resp, err := c.doRequest("POST", "/v1/verify/bulk", apiKey, map[string]interface{}{
		"emails":     emails,
		"check_smtp": checkSMTP,
	})
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// GetAccountBalance retrieves the account credit balance.
func (c *APIClient) GetAccountBalance(apiKey string) (map[string]interface{}, error) {
	resp, err := c.doRequest("GET", "/v1/credits", apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// GetTaskStatus returns the status of an async verification job.
func (c *APIClient) GetTaskStatus(apiKey, taskID string) (map[string]interface{}, error) {
	resp, err := c.doRequest("GET", fmt.Sprintf("/v1/verify/file/%s", taskID), apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// GetVerificationHistory retrieves paginated verification history.
func (c *APIClient) GetVerificationHistory(apiKey string, page, limit int) (map[string]interface{}, error) {
	resp, err := c.doRequest("GET", fmt.Sprintf("/v1/history?page=%d&limit=%d", page, limit), apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// GetVerificationStats retrieves verification statistics.
func (c *APIClient) GetVerificationStats(apiKey, period string) (map[string]interface{}, error) {
	resp, err := c.doRequest("GET", fmt.Sprintf("/v1/stats?period=%s", period), apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// GetDownloadURL returns the download URL for verification results.
func (c *APIClient) GetDownloadURL(apiKey, jobID string, filters map[string]bool) (map[string]interface{}, error) {
	// Build query string from filters
	path := fmt.Sprintf("/v1/verify/file/%s/results", jobID)
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

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		// Fall back to constructed URL
		return map[string]interface{}{
			"download_url": c.baseURL + path,
			"message":      "Use this URL with your BV-API-KEY header to download results",
		}, nil
	}
	return result, nil
}

// CreateWebhook creates a new webhook.
func (c *APIClient) CreateWebhook(apiKey, url string, events []string) (map[string]interface{}, error) {
	resp, err := c.doRequest("POST", "/v1/webhooks", apiKey, map[string]interface{}{
		"url":    url,
		"events": events,
	})
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// ListWebhooks retrieves all webhooks for the account.
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

// DeleteWebhook removes a webhook by ID.
func (c *APIClient) DeleteWebhook(apiKey, webhookID string) (map[string]interface{}, error) {
	resp, err := c.doRequest("DELETE", fmt.Sprintf("/v1/webhooks/%s", webhookID), apiKey, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		// DELETE may return empty body
		return map[string]interface{}{
			"success": true,
			"message": "Webhook deleted successfully",
		}, nil
	}
	return result, nil
}
