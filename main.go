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
	version = "1.0.0" // 版本升级：添加 Webhook 和下载 URL 工具，修复资源 URI 解析
)

// MCP Server 上下文
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
	// 解析命令行参数
	logLevel := flag.String("log", "info", "Log level (debug, info, warn, error)")
	httpPort := flag.String("port", "9000", "HTTP server port")
	apiBaseURL := flag.String("api-url", "", "External API base URL (default: https://api.billionverify.com)")
	flag.Parse()

	logger := logrus.New()

	// 配置日志级别
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stderr)

	logger.Infof("🚀 Starting BillionVerify MCP Server v%s (API Proxy Mode)", version)

	// 确定 API 基础 URL
	baseURL := *apiBaseURL
	if baseURL == "" {
		// 从环境变量获取，或使用默认值
		baseURL = os.Getenv("API_BASE_URL")
		if baseURL == "" {
			// K3s 集群内部服务地址
			baseURL = "https://api.billionverify.com"
		}
	}
	logger.Infof("📡 API Base URL: %s", baseURL)

	// 创建 API 客户端
	apiClient := NewAPIClient(baseURL, logger)

	// 存储到全局上下文
	mcpContext = &struct {
		logger    *logrus.Logger
		apiClient *APIClient
	}{
		logger:    logger,
		apiClient: apiClient,
	}

	// 创建 MCP Server
	logger.Info("📡 Creating MCP server...")
	s := server.NewMCPServer("billionverify-mcp", version,
		server.WithLogging(),
	)

	// 注册工具
	addTools(s, logger)
	logger.Debug("✓ Tools registered successfully")

	// 注册资源
	addResources(s, logger)
	logger.Debug("✓ Resources registered successfully")

	// 设置优雅关闭
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-sigChan
		logger.Info("🛑 Shutdown signal received, gracefully stopping server")
		cancel()
		os.Exit(0)
	}()

	// 启动 HTTP 服务器
	httpTransport := NewHTTPTransport(s, logger)

	// 启动会话清理
	go httpTransport.CleanupSessions(ctx)

	// 创建 HTTP 路由
	http.HandleFunc("/mcp", httpTransport.HandleMCPRequest)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"version": version,
			"service": "billionverify-mcp",
			"mode":    "api-proxy",
		})
	})

	addr := fmt.Sprintf("0.0.0.0:%s", *httpPort)
	logger.Infof("🚀 BillionVerify MCP Server v%s starting...", version)
	logger.Infof("✅ HTTP server listening on %s", addr)
	mcpDomain := os.Getenv("MCP_ENDPOINT_URL")
	if mcpDomain == "" {
		mcpDomain = "https://mcp.billionverify.com"
	}
	logger.Infof("📡 Endpoint: %s/mcp?api_key=YOUR_API_KEY", mcpDomain)

	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Fatalf("HTTP server error: %v", err)
	}
}

// addTools 注册所有 MCP 工具
func addTools(s *server.MCPServer, logger *logrus.Logger) {
	// 健康检查工具
	healthTool := mcp.NewTool("health_check",
		mcp.WithDescription("检查 BillionVerify MCP 服务器的健康状态"),
	)
	s.AddTool(healthTool, healthCheckHandler)

	// 单个邮箱验证工具
	verifyEmailTool := mcp.NewTool("verify_single_email",
		mcp.WithDescription("验证单个邮箱地址"),
		mcp.WithString("email"),
		mcp.WithString("api_key"),
		mcp.WithBoolean("check_smtp"),
		mcp.WithBoolean("force_refresh"),
	)
	s.AddTool(verifyEmailTool, verifySingleEmailHandler)

	// 批量邮箱验证工具
	batchEmailTool := mcp.NewTool("verify_batch_emails",
		mcp.WithDescription("批量验证多个邮箱地址（最多 50 个）"),
		mcp.WithArray("emails"),
		mcp.WithString("api_key"),
		mcp.WithBoolean("check_smtp"),
	)
	s.AddTool(batchEmailTool, verifyBatchEmailsHandler)

	// 获取账户余额工具
	balanceTool := mcp.NewTool("get_account_balance",
		mcp.WithDescription("查询账户积分余额"),
		mcp.WithString("api_key"),
	)
	s.AddTool(balanceTool, getAccountBalanceHandler)

	// 获取任务状态工具
	statusTool := mcp.NewTool("get_task_status",
		mcp.WithDescription("查询异步任务的处理状态"),
		mcp.WithString("api_key"),
		mcp.WithString("task_id"),
	)
	s.AddTool(statusTool, getTaskStatusHandler)

	// 获取下载 URL 工具
	downloadTool := mcp.NewTool("get_download_url",
		mcp.WithDescription("获取文件验证结果的下载 URL，支持按状态过滤"),
		mcp.WithString("api_key"),
		mcp.WithString("job_id"),
		mcp.WithBoolean("valid"),
		mcp.WithBoolean("invalid"),
		mcp.WithBoolean("catchall"),
		mcp.WithBoolean("role"),
		mcp.WithBoolean("disposable"),
		mcp.WithBoolean("unknown"),
	)
	s.AddTool(downloadTool, getDownloadURLHandler)

	// 创建 Webhook 工具
	createWebhookTool := mcp.NewTool("create_webhook",
		mcp.WithDescription("创建一个新的 Webhook 用于接收验证完成通知"),
		mcp.WithString("api_key"),
		mcp.WithString("url"),
		mcp.WithArray("events"),
	)
	s.AddTool(createWebhookTool, createWebhookHandler)

	// 列出 Webhook 工具
	listWebhooksTool := mcp.NewTool("list_webhooks",
		mcp.WithDescription("列出当前账户的所有 Webhook"),
		mcp.WithString("api_key"),
	)
	s.AddTool(listWebhooksTool, listWebhooksHandler)

	// 删除 Webhook 工具
	deleteWebhookTool := mcp.NewTool("delete_webhook",
		mcp.WithDescription("删除指定的 Webhook"),
		mcp.WithString("api_key"),
		mcp.WithString("webhook_id"),
	)
	s.AddTool(deleteWebhookTool, deleteWebhookHandler)
}

// addResources 注册所有 MCP 资源
func addResources(s *server.MCPServer, logger *logrus.Logger) {
	// 账户信息资源
	accountResource := mcp.Resource{
		URI:         "billionverify://account/info",
		Name:        "Account Information",
		Description: "获取账户信息，包括余额、使用统计等",
		MIMEType:    "application/json",
	}
	s.AddResource(accountResource, accountInfoHandler)

	// 验证历史资源
	historyResource := mcp.Resource{
		URI:         "billionverify://history/summary",
		Name:        "Verification History",
		Description: "获取验证历史摘要",
		MIMEType:    "application/json",
	}
	s.AddResource(historyResource, historyHandler)

	// 验证统计资源
	statsResource := mcp.Resource{
		URI:         "billionverify://stats/verification",
		Name:        "Verification Statistics",
		Description: "获取验证统计数据",
		MIMEType:    "application/json",
	}
	s.AddResource(statsResource, statsHandler)
}

// ======================== 工具处理器 ========================

func healthCheckHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	mcpContext.logger.Debug("Health check tool called")

	response := map[string]interface{}{
		"status":    "healthy",
		"version":   version,
		"service":   "billionverify-mcp",
		"mode":      "api-proxy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"message":   "MCP 服务器正常运行（API 代理模式）",
	}

	content := mcp.NewTextContent(formatJSON(response))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
	}, nil
}

func verifySingleEmailHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. 提取 API Key
	apiKey, err := extractAPIKey(request)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	// 2. 提取邮箱参数
	email, err := request.RequireString("email")
	if err != nil {
		mcpContext.logger.Warnf("Missing email parameter: %v", err)
		return errorResult("Missing email parameter"), nil
	}

	// 提取可选参数
	checkSMTP := getBoolParam(request, "check_smtp", false)
	forceRefresh := getBoolParam(request, "force_refresh", false)

	mcpContext.logger.Infof("Verify single email: %s (checkSMTP=%v, forceRefresh=%v)", email, checkSMTP, forceRefresh)

	// 3. 调用外部 API
	result, err := mcpContext.apiClient.VerifySingleEmail(apiKey, email, checkSMTP, forceRefresh)
	if err != nil {
		mcpContext.logger.Errorf("API call failed: %v", err)
		return errorResult("Failed to verify email: " + err.Error()), nil
	}

	content := mcp.NewTextContent(formatJSON(result))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
	}, nil
}

func verifyBatchEmailsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. 提取 API Key
	apiKey, err := extractAPIKey(request)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	// 2. 提取邮箱列表
	emails, err := request.RequireStringSlice("emails")
	if err != nil {
		mcpContext.logger.Warnf("Missing or invalid emails parameter: %v", err)
		return errorResult("Missing or invalid emails parameter"), nil
	}

	if len(emails) == 0 || len(emails) > 50 {
		return errorResult(fmt.Sprintf("邮箱数量必须在 1-50 之间，当前数量: %d", len(emails))), nil
	}

	checkSMTP := getBoolParam(request, "check_smtp", false)

	mcpContext.logger.Infof("Verify batch emails: %d emails (checkSMTP=%v)", len(emails), checkSMTP)

	// 3. 调用外部 API
	result, err := mcpContext.apiClient.VerifyBatchEmails(apiKey, emails, checkSMTP)
	if err != nil {
		mcpContext.logger.Errorf("API call failed: %v", err)
		return errorResult("Failed to verify batch emails: " + err.Error()), nil
	}

	content := mcp.NewTextContent(formatJSON(result))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
	}, nil
}

func getAccountBalanceHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. 提取 API Key
	apiKey, err := extractAPIKey(request)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	mcpContext.logger.Info("Get account balance requested")

	// 2. 调用外部 API
	result, err := mcpContext.apiClient.GetAccountBalance(apiKey)
	if err != nil {
		mcpContext.logger.Errorf("API call failed: %v", err)
		return errorResult("Failed to get account balance: " + err.Error()), nil
	}

	content := mcp.NewTextContent(formatJSON(result))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
	}, nil
}

func getTaskStatusHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. 提取 API Key
	apiKey, err := extractAPIKey(request)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	// 2. 提取任务 ID
	taskID, err := request.RequireString("task_id")
	if err != nil {
		mcpContext.logger.Warnf("Missing task_id parameter: %v", err)
		return errorResult("Missing task_id parameter"), nil
	}

	mcpContext.logger.Infof("Get task status: taskId=%s", taskID)

	// 3. 调用外部 API
	result, err := mcpContext.apiClient.GetTaskStatus(apiKey, taskID)
	if err != nil {
		mcpContext.logger.Errorf("API call failed: %v", err)
		return errorResult("Failed to get task status: " + err.Error()), nil
	}

	content := mcp.NewTextContent(formatJSON(result))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
	}, nil
}

func getDownloadURLHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. 提取 API Key
	apiKey, err := extractAPIKey(request)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	// 2. 提取 Job ID
	jobID, err := request.RequireString("job_id")
	if err != nil {
		mcpContext.logger.Warnf("Missing job_id parameter: %v", err)
		return errorResult("Missing job_id parameter"), nil
	}

	// 3. 提取过滤参数
	filters := make(map[string]bool)
	filterNames := []string{"valid", "invalid", "catchall", "role", "disposable", "unknown"}
	for _, name := range filterNames {
		if val := getBoolParam(request, name, false); val {
			filters[name] = true
		}
	}

	mcpContext.logger.Infof("Get download URL: jobId=%s, filters=%v", jobID, filters)

	// 4. 调用外部 API
	result, err := mcpContext.apiClient.GetDownloadURL(apiKey, jobID, filters)
	if err != nil {
		mcpContext.logger.Errorf("API call failed: %v", err)
		return errorResult("Failed to get download URL: " + err.Error()), nil
	}

	content := mcp.NewTextContent(formatJSON(result))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
	}, nil
}

func createWebhookHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. 提取 API Key
	apiKey, err := extractAPIKey(request)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	// 2. 提取 URL
	webhookURL, err := request.RequireString("url")
	if err != nil {
		mcpContext.logger.Warnf("Missing url parameter: %v", err)
		return errorResult("Missing url parameter"), nil
	}

	// 3. 提取事件列表
	events, err := request.RequireStringSlice("events")
	if err != nil {
		mcpContext.logger.Warnf("Missing or invalid events parameter: %v", err)
		return errorResult("Missing or invalid events parameter"), nil
	}

	mcpContext.logger.Infof("Create webhook: url=%s, events=%v", webhookURL, events)

	// 4. 调用外部 API
	result, err := mcpContext.apiClient.CreateWebhook(apiKey, webhookURL, events)
	if err != nil {
		mcpContext.logger.Errorf("API call failed: %v", err)
		return errorResult("Failed to create webhook: " + err.Error()), nil
	}

	content := mcp.NewTextContent(formatJSON(result))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
	}, nil
}

func listWebhooksHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. 提取 API Key
	apiKey, err := extractAPIKey(request)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	mcpContext.logger.Info("List webhooks requested")

	// 2. 调用外部 API
	result, err := mcpContext.apiClient.ListWebhooks(apiKey)
	if err != nil {
		mcpContext.logger.Errorf("API call failed: %v", err)
		return errorResult("Failed to list webhooks: " + err.Error()), nil
	}

	content := mcp.NewTextContent(formatJSON(result))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
	}, nil
}

func deleteWebhookHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. 提取 API Key
	apiKey, err := extractAPIKey(request)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	// 2. 提取 Webhook ID
	webhookID, err := request.RequireString("webhook_id")
	if err != nil {
		mcpContext.logger.Warnf("Missing webhook_id parameter: %v", err)
		return errorResult("Missing webhook_id parameter"), nil
	}

	mcpContext.logger.Infof("Delete webhook: webhookId=%s", webhookID)

	// 3. 调用外部 API
	result, err := mcpContext.apiClient.DeleteWebhook(apiKey, webhookID)
	if err != nil {
		mcpContext.logger.Errorf("API call failed: %v", err)
		return errorResult("Failed to delete webhook: " + err.Error()), nil
	}

	content := mcp.NewTextContent(formatJSON(result))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
	}, nil
}

// ======================== 资源处理器 ========================

func accountInfoHandler(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	apiKey := extractAPIKeyFromURI(request.Params.URI)
	if apiKey == "" {
		return nil, fmt.Errorf("missing api_key parameter in URI")
	}

	result, err := mcpContext.apiClient.GetAccountBalance(apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get account info: %w", err)
	}

	return []mcp.ResourceContents{
		&mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "application/json",
			Text:     formatJSON(result),
		},
	}, nil
}

func historyHandler(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	apiKey := extractAPIKeyFromURI(request.Params.URI)
	if apiKey == "" {
		return nil, fmt.Errorf("missing api_key parameter in URI")
	}

	// 默认分页参数
	page := 1
	limit := 20

	result, err := mcpContext.apiClient.GetVerificationHistory(apiKey, page, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get history: %w", err)
	}

	return []mcp.ResourceContents{
		&mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "application/json",
			Text:     formatJSON(result),
		},
	}, nil
}

func statsHandler(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	apiKey := extractAPIKeyFromURI(request.Params.URI)
	if apiKey == "" {
		return nil, fmt.Errorf("missing api_key parameter in URI")
	}

	// 默认查询月度统计
	period := "month"

	result, err := mcpContext.apiClient.GetVerificationStats(apiKey, period)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	return []mcp.ResourceContents{
		&mcp.TextResourceContents{
			URI:      request.Params.URI,
			MIMEType: "application/json",
			Text:     formatJSON(result),
		},
	}, nil
}

// ======================== 辅助函数 ========================

func extractAPIKey(request mcp.CallToolRequest) (string, error) {
	args := request.GetArguments()
	if apiKey, ok := args["api_key"].(string); ok && apiKey != "" {
		return apiKey, nil
	}
	return "", fmt.Errorf("missing or invalid api_key parameter")
}

func extractAPIKeyFromURI(uri string) string {
	// 从 URI 查询参数中提取 api_key
	// 格式: billionverify://account/info?api_key=xxx

	// 尝试解析 URI
	parsed, err := url.Parse(uri)
	if err != nil {
		mcpContext.logger.Warnf("Failed to parse URI: %v", err)
		return ""
	}

	// 从查询参数中提取 api_key
	apiKey := parsed.Query().Get("api_key")
	if apiKey != "" {
		return apiKey
	}

	// 尝试从 fragment 中提取（某些客户端可能使用 fragment）
	if parsed.Fragment != "" {
		fragValues, err := url.ParseQuery(parsed.Fragment)
		if err == nil {
			if key := fragValues.Get("api_key"); key != "" {
				return key
			}
		}
	}

	return ""
}

func getBoolParam(request mcp.CallToolRequest, name string, defaultValue bool) bool {
	if val, ok := request.GetArguments()[name]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

func errorResult(message string) *mcp.CallToolResult {
	response := map[string]interface{}{
		"error":   true,
		"message": message,
	}
	content := mcp.NewTextContent(formatJSON(response))
	return &mcp.CallToolResult{
		Content: []mcp.Content{content},
		IsError: true,
	}
}

func formatJSON(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": \"failed to format JSON: %v\"}", err)
	}
	return string(data)
}
