package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/sirupsen/logrus"
)

var (
	version = "1.0.0"
)

// mcpContext holds global server state.
var mcpContext *struct {
	logger    *logrus.Logger
	apiClient *APIClient
}

func init() {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stderr)
}

func main() {
	// Parse CLI flags
	logLevel := flag.String("log", "info", "Log level (debug, info, warn, error)")
	httpPort := flag.String("port", "9000", "HTTP server port")
	apiBaseURL := flag.String("api-url", "", "External API base URL (default: https://api.billionverify.com)")
	flag.Parse()

	logger := logrus.New()

	// Configure log level
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stderr)

	logger.Infof("Starting BillionVerify MCP Server v%s", version)

	// Resolve API base URL: flag > env > default
	baseURL := *apiBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("BILLIONVERIFY_API_URL")
		if baseURL == "" {
			baseURL = "https://api.billionverify.com"
		}
	}
	logger.Infof("API base URL: %s", baseURL)

	// Create API client
	apiClient := NewAPIClient(baseURL, logger)

	// Store in global context
	mcpContext = &struct {
		logger    *logrus.Logger
		apiClient *APIClient
	}{
		logger:    logger,
		apiClient: apiClient,
	}

	// Create MCP server
	s := server.NewMCPServer("billionverify-mcp", version,
		server.WithLogging(),
	)

	// Register tools
	addTools(s, logger)
	logger.Debug("Tools registered")

	// Register resources
	addResources(s, logger)
	logger.Debug("Resources registered")

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-sigChan
		logger.Info("Shutdown signal received")
		cancel()
		os.Exit(0)
	}()

	// Start HTTP transport
	httpTransport := NewHTTPTransport(s, logger)

	// Start session cleanup goroutine
	go httpTransport.CleanupSessions(ctx)

	// Register HTTP routes
	http.HandleFunc("/mcp", httpTransport.HandleMCPRequest)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"version": version,
			"service": "billionverify-mcp",
		})
	})

	addr := fmt.Sprintf("0.0.0.0:%s", *httpPort)
	logger.Infof("BillionVerify MCP Server v%s listening on %s", version, addr)

	mcpDomain := os.Getenv("MCP_ENDPOINT_URL")
	if mcpDomain == "" {
		mcpDomain = "https://mcp.billionverify.com"
	}
	logger.Infof("Public endpoint: %s/mcp?api_key=YOUR_API_KEY", mcpDomain)

	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Fatalf("HTTP server error: %v", err)
	}
}

// addTools registers all MCP tools.
func addTools(s *server.MCPServer, logger *logrus.Logger) {
	healthTool := mcp.NewTool("health_check",
		mcp.WithDescription("Check BillionVerify MCP server health status"),
	)
	s.AddTool(healthTool, healthCheckHandler)

	verifyEmailTool := mcp.NewTool("verify_single_email",
		mcp.WithDescription("Verify a single email address"),
		mcp.WithString("email"),
		mcp.WithString("api_key"),
		mcp.WithBoolean("check_smtp"),
		mcp.WithBoolean("force_refresh"),
	)
	s.AddTool(verifyEmailTool, verifySingleEmailHandler)

	// verify_batch_emails accepts an array of email strings via the "emails" argument.
	verifyBatchTool := mcp.NewTool("verify_batch_emails",
		mcp.WithDescription("Verify multiple email addresses (up to 50)"),
		mcp.WithString("api_key"),
		mcp.WithBoolean("check_smtp"),
	)
	s.AddTool(verifyBatchTool, verifyBatchEmailsHandler)

	balanceTool := mcp.NewTool("get_account_balance",
		mcp.WithDescription("Get account credit balance"),
		mcp.WithString("api_key"),
	)
	s.AddTool(balanceTool, getAccountBalanceHandler)

	taskStatusTool := mcp.NewTool("get_task_status",
		mcp.WithDescription("Get async file verification job status"),
		mcp.WithString("api_key"),
		mcp.WithString("task_id"),
	)
	s.AddTool(taskStatusTool, getTaskStatusHandler)

	downloadURLTool := mcp.NewTool("get_download_url",
		mcp.WithDescription("Get download URL for file verification results, with optional status filters"),
		mcp.WithString("api_key"),
		mcp.WithString("job_id"),
		mcp.WithBoolean("valid"),
		mcp.WithBoolean("invalid"),
		mcp.WithBoolean("catchall"),
		mcp.WithBoolean("role"),
		mcp.WithBoolean("disposable"),
		mcp.WithBoolean("unknown"),
	)
	s.AddTool(downloadURLTool, getDownloadURLHandler)

	// create_webhook accepts an array of event strings via the "events" argument.
	createWebhookTool := mcp.NewTool("create_webhook",
		mcp.WithDescription("Create a webhook to receive file verification completion notifications"),
		mcp.WithString("api_key"),
		mcp.WithString("url"),
	)
	s.AddTool(createWebhookTool, createWebhookHandler)

	listWebhooksTool := mcp.NewTool("list_webhooks",
		mcp.WithDescription("List all webhooks for the account"),
		mcp.WithString("api_key"),
	)
	s.AddTool(listWebhooksTool, listWebhooksHandler)

	deleteWebhookTool := mcp.NewTool("delete_webhook",
		mcp.WithDescription("Delete a webhook by ID"),
		mcp.WithString("api_key"),
		mcp.WithString("webhook_id"),
	)
	s.AddTool(deleteWebhookTool, deleteWebhookHandler)
}

// addResources registers all MCP resources.
func addResources(s *server.MCPServer, logger *logrus.Logger) {
	s.AddResource(mcp.Resource{
		URI:         "billionverify://account/info",
		Name:        "Account Information",
		Description: "Account information including balance and usage statistics",
		MIMEType:    "application/json",
	}, accountInfoHandler)

	s.AddResource(mcp.Resource{
		URI:         "billionverify://history/summary",
		Name:        "Verification History",
		Description: "Verification history summary",
		MIMEType:    "application/json",
	}, historyHandler)

	s.AddResource(mcp.Resource{
		URI:         "billionverify://stats/verification",
		Name:        "Verification Statistics",
		Description: "Verification statistics",
		MIMEType:    "application/json",
	}, statsHandler)
}

// ======================== Tool Handlers ========================

func healthCheckHandler(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	response := map[string]interface{}{
		"status":    "healthy",
		"version":   version,
		"service":   "billionverify-mcp",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	return mcp.NewToolResultText(formatJSON(response)), nil
}

func verifySingleEmailHandler(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	apiKey, err := extractAPIKey(arguments)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	email, ok := arguments["email"].(string)
	if !ok || email == "" {
		return mcp.NewToolResultError("Missing email parameter"), nil
	}

	checkSMTP := getBoolArg(arguments, "check_smtp", false)
	forceRefresh := getBoolArg(arguments, "force_refresh", false)

	mcpContext.logger.Infof("verify_single_email: %s (smtp=%v refresh=%v)", email, checkSMTP, forceRefresh)

	result, err := mcpContext.apiClient.VerifySingleEmail(apiKey, email, checkSMTP, forceRefresh)
	if err != nil {
		mcpContext.logger.Errorf("API error: %v", err)
		return mcp.NewToolResultError("Failed to verify email: " + err.Error()), nil
	}

	return mcp.NewToolResultText(formatJSON(result)), nil
}

func verifyBatchEmailsHandler(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	apiKey, err := extractAPIKey(arguments)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	emails, err := extractStringSlice(arguments, "emails")
	if err != nil {
		return mcp.NewToolResultError("Missing or invalid emails parameter"), nil
	}

	if len(emails) == 0 || len(emails) > 50 {
		return mcp.NewToolResultError(fmt.Sprintf("email count must be 1-50, got %d", len(emails))), nil
	}

	checkSMTP := getBoolArg(arguments, "check_smtp", false)

	mcpContext.logger.Infof("verify_batch_emails: %d emails (smtp=%v)", len(emails), checkSMTP)

	result, err := mcpContext.apiClient.VerifyBatchEmails(apiKey, emails, checkSMTP)
	if err != nil {
		mcpContext.logger.Errorf("API error: %v", err)
		return mcp.NewToolResultError("Failed to verify batch emails: " + err.Error()), nil
	}

	return mcp.NewToolResultText(formatJSON(result)), nil
}

func getAccountBalanceHandler(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	apiKey, err := extractAPIKey(arguments)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := mcpContext.apiClient.GetAccountBalance(apiKey)
	if err != nil {
		mcpContext.logger.Errorf("API error: %v", err)
		return mcp.NewToolResultError("Failed to get account balance: " + err.Error()), nil
	}

	return mcp.NewToolResultText(formatJSON(result)), nil
}

func getTaskStatusHandler(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	apiKey, err := extractAPIKey(arguments)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	taskID, ok := arguments["task_id"].(string)
	if !ok || taskID == "" {
		return mcp.NewToolResultError("Missing task_id parameter"), nil
	}

	mcpContext.logger.Infof("get_task_status: %s", taskID)

	result, err := mcpContext.apiClient.GetTaskStatus(apiKey, taskID)
	if err != nil {
		mcpContext.logger.Errorf("API error: %v", err)
		return mcp.NewToolResultError("Failed to get task status: " + err.Error()), nil
	}

	return mcp.NewToolResultText(formatJSON(result)), nil
}

func getDownloadURLHandler(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	apiKey, err := extractAPIKey(arguments)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	jobID, ok := arguments["job_id"].(string)
	if !ok || jobID == "" {
		return mcp.NewToolResultError("Missing job_id parameter"), nil
	}

	filters := make(map[string]bool)
	for _, name := range []string{"valid", "invalid", "catchall", "role", "disposable", "unknown"} {
		if getBoolArg(arguments, name, false) {
			filters[name] = true
		}
	}

	mcpContext.logger.Infof("get_download_url: job=%s filters=%v", jobID, filters)

	result, err := mcpContext.apiClient.GetDownloadURL(apiKey, jobID, filters)
	if err != nil {
		mcpContext.logger.Errorf("API error: %v", err)
		return mcp.NewToolResultError("Failed to get download URL: " + err.Error()), nil
	}

	return mcp.NewToolResultText(formatJSON(result)), nil
}

func createWebhookHandler(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	apiKey, err := extractAPIKey(arguments)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	webhookURL, ok := arguments["url"].(string)
	if !ok || webhookURL == "" {
		return mcp.NewToolResultError("Missing url parameter"), nil
	}

	events, err := extractStringSlice(arguments, "events")
	if err != nil {
		return mcp.NewToolResultError("Missing or invalid events parameter"), nil
	}

	mcpContext.logger.Infof("create_webhook: url=%s events=%v", webhookURL, events)

	result, err := mcpContext.apiClient.CreateWebhook(apiKey, webhookURL, events)
	if err != nil {
		mcpContext.logger.Errorf("API error: %v", err)
		return mcp.NewToolResultError("Failed to create webhook: " + err.Error()), nil
	}

	return mcp.NewToolResultText(formatJSON(result)), nil
}

func listWebhooksHandler(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	apiKey, err := extractAPIKey(arguments)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result, err := mcpContext.apiClient.ListWebhooks(apiKey)
	if err != nil {
		mcpContext.logger.Errorf("API error: %v", err)
		return mcp.NewToolResultError("Failed to list webhooks: " + err.Error()), nil
	}

	return mcp.NewToolResultText(formatJSON(result)), nil
}

func deleteWebhookHandler(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	apiKey, err := extractAPIKey(arguments)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	webhookID, ok := arguments["webhook_id"].(string)
	if !ok || webhookID == "" {
		return mcp.NewToolResultError("Missing webhook_id parameter"), nil
	}

	mcpContext.logger.Infof("delete_webhook: %s", webhookID)

	result, err := mcpContext.apiClient.DeleteWebhook(apiKey, webhookID)
	if err != nil {
		mcpContext.logger.Errorf("API error: %v", err)
		return mcp.NewToolResultError("Failed to delete webhook: " + err.Error()), nil
	}

	return mcp.NewToolResultText(formatJSON(result)), nil
}

// ======================== Resource Handlers ========================

func accountInfoHandler(request mcp.ReadResourceRequest) ([]interface{}, error) {
	apiKey := extractAPIKeyFromURI(request.Params.URI)
	if apiKey == "" {
		return nil, fmt.Errorf("missing api_key in URI")
	}

	result, err := mcpContext.apiClient.GetAccountBalance(apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get account info: %w", err)
	}

	return []interface{}{
		mcp.TextResourceContents{
			ResourceContents: mcp.ResourceContents{
				URI:      request.Params.URI,
				MIMEType: "application/json",
			},
			Text: formatJSON(result),
		},
	}, nil
}

func historyHandler(request mcp.ReadResourceRequest) ([]interface{}, error) {
	apiKey := extractAPIKeyFromURI(request.Params.URI)
	if apiKey == "" {
		return nil, fmt.Errorf("missing api_key in URI")
	}

	result, err := mcpContext.apiClient.GetVerificationHistory(apiKey, 1, 20)
	if err != nil {
		return nil, fmt.Errorf("failed to get history: %w", err)
	}

	return []interface{}{
		mcp.TextResourceContents{
			ResourceContents: mcp.ResourceContents{
				URI:      request.Params.URI,
				MIMEType: "application/json",
			},
			Text: formatJSON(result),
		},
	}, nil
}

func statsHandler(request mcp.ReadResourceRequest) ([]interface{}, error) {
	apiKey := extractAPIKeyFromURI(request.Params.URI)
	if apiKey == "" {
		return nil, fmt.Errorf("missing api_key in URI")
	}

	result, err := mcpContext.apiClient.GetVerificationStats(apiKey, "month")
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	return []interface{}{
		mcp.TextResourceContents{
			ResourceContents: mcp.ResourceContents{
				URI:      request.Params.URI,
				MIMEType: "application/json",
			},
			Text: formatJSON(result),
		},
	}, nil
}

// ======================== Helpers ========================

func extractAPIKey(arguments map[string]interface{}) (string, error) {
	if apiKey, ok := arguments["api_key"].(string); ok && apiKey != "" {
		return apiKey, nil
	}
	// Fall back to environment variable
	if apiKey := os.Getenv("BILLIONVERIFY_API_KEY"); apiKey != "" {
		return apiKey, nil
	}
	return "", fmt.Errorf("missing api_key: set BILLIONVERIFY_API_KEY env var or pass api_key parameter")
}

func extractAPIKeyFromURI(uri string) string {
	// Format: billionverify://account/info?api_key=xxx
	parsed, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	if key := parsed.Query().Get("api_key"); key != "" {
		return key
	}
	// Also check fragment (some clients use it)
	if parsed.Fragment != "" {
		if vals, err := url.ParseQuery(parsed.Fragment); err == nil {
			if key := vals.Get("api_key"); key != "" {
				return key
			}
		}
	}
	return ""
}

func getBoolArg(arguments map[string]interface{}, name string, defaultValue bool) bool {
	if val, ok := arguments[name]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// extractStringSlice converts a JSON array argument to []string.
func extractStringSlice(arguments map[string]interface{}, name string) ([]string, error) {
	raw, ok := arguments[name]
	if !ok {
		return nil, fmt.Errorf("missing argument: %s", name)
	}
	slice, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("argument %s is not an array", name)
	}
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("argument %s contains non-string element", name)
		}
		result = append(result, s)
	}
	return result, nil
}

func formatJSON(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": \"failed to format JSON: %v\"}", err)
	}
	return string(data)
}
