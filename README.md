# BillionVerify MCP Server — Go

Connect any AI assistant to [BillionVerify](https://billionverify.com) email verification via the [Model Context Protocol](https://modelcontextprotocol.io).

Also available in [Python](https://github.com/BillionVerify/python-mcp-server) and [TypeScript](https://github.com/BillionVerify/typescript-mcp-server).

---

## Option 1 — Online Server (No Installation)

Use BillionVerify's hosted MCP server at `https://mcp.billionverify.com/mcp`. No setup required — just add your API key.

Get your API key from the [BillionVerify Dashboard](https://billionverify.com/auth/sign-in?next=/home/api-keys).

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "billionverify": {
      "command": "curl",
      "args": ["--stdio", "https://mcp.billionverify.com/mcp?api_key=YOUR_API_KEY"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add billionverify -- curl --stdio "https://mcp.billionverify.com/mcp?api_key=YOUR_API_KEY"
```

### Cursor

Go to **Settings → MCP** and add the same JSON configuration as Claude Desktop above.

---

## Option 2 — Self-Hosted (Go)

Run your own MCP server using this Go implementation.

### Prerequisites

- Go 1.21+

### Install

```bash
go install github.com/BillionVerify/go-mcp-server@latest
```

### Run (stdio — for Claude Desktop / Claude Code)

```bash
BILLIONVERIFY_API_KEY=your_api_key billionverify-mcp
```

### Claude Desktop config (self-hosted)

```json
{
  "mcpServers": {
    "billionverify": {
      "command": "billionverify-mcp",
      "env": {
        "BILLIONVERIFY_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### Run (HTTP server mode)

```bash
BILLIONVERIFY_API_KEY=your_api_key billionverify-mcp --transport http --port 9000
```

Then connect to `http://localhost:9000/mcp?api_key=your_api_key`.

### Build from source

```bash
git clone https://github.com/BillionVerify/go-mcp-server.git
cd go-mcp-server
go build -o billionverify-mcp .
```

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `BILLIONVERIFY_API_KEY` | Your BillionVerify API key | — |
| `BILLIONVERIFY_API_URL` | API base URL override | `https://api.billionverify.com` |

### CLI Flags

| Flag | Description | Default |
|---|---|---|
| `--port` | HTTP server port | `9000` |
| `--log` | Log level (`debug`, `info`, `warn`, `error`) | `info` |
| `--api-url` | API base URL override | `https://api.billionverify.com` |

---

## Available Tools

| Tool | Description |
|---|---|
| `verify_single_email` | Verify a single email address in real-time |
| `verify_batch_emails` | Verify up to 50 emails in one request |
| `get_account_balance` | Check your credit balance |
| `get_task_status` | Poll the status of an async file verification job |
| `get_download_url` | Get download URL for results with status filters |
| `create_webhook` | Subscribe to file completion events |
| `list_webhooks` | List all configured webhooks |
| `delete_webhook` | Remove a webhook |
| `health_check` | Check server health |

---

## License

MIT
