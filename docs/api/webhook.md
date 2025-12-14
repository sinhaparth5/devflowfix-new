# Webhook Secret Management API

Secure webhook secret management for DevFlowFix.

---

## API Endpoints

### 1. Generate Webhook Secret

**Endpoint:** `POST /api/v1/webhook/secret/generate/me`

**Description:** Generate a new cryptographically secure webhook secret for the authenticated user.

**Authentication:** Required (Bearer token)

**Request Headers:**
```
Authorization: Bearer <your_access_token>
Content-Type: application/json
```

**Request Body:** None

**Response:** `201 Created`

```json
{
  "success": true,
  "message": "Webhook secret generated successfully",
  "user": {
    "user_id": "dev_abc123xyz456",
    "email": "user@example.com",
    "full_name": "John Doe"
  },
  "webhook_secret": "xyzABC123def456GHI789jkl012MNO345pqr678STU901vwx234YZA567bcd890EFG",
  "webhook_url": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456",
  "secret_length": 64,
  "algorithm": "HMAC-SHA256",
  "created_at": "2025-12-13T20:30:00.000000Z",
  "github_configuration": {
    "payload_url": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456",
    "content_type": "application/json",
    "secret": "xyzABC123def456GHI789jkl012MNO345pqr678STU901vwx234YZA567bcd890EFG",
    "ssl_verification": "Enable SSL verification",
    "events": ["workflow_run", "check_run"],
    "active": true
  },
  "setup_instructions": {
    "step_1": {
      "action": "Copy your webhook secret",
      "value": "xyzABC123def456GHI789jkl012MNO345pqr678STU901vwx234YZA567bcd890EFG",
      "note": "Save this secret now - it will not be shown again"
    },
    "step_2": {
      "action": "Go to your GitHub repository",
      "url": "https://github.com/YOUR_ORG/YOUR_REPO/settings/hooks"
    },
    "step_3": {
      "action": "Click 'Add webhook'"
    },
    "step_4": {
      "action": "Configure webhook settings",
      "payload_url": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456",
      "content_type": "application/json",
      "secret": "xyzABC123def456GHI789jkl012MNO345pqr678STU901vwx234YZA567bcd890EFG"
    },
    "step_5": {
      "action": "Select events",
      "individual_events": ["Workflow runs", "Check runs"],
      "note": "Uncheck 'Just the push event' and select individual events"
    },
    "step_6": {
      "action": "Ensure 'Active' is checked"
    },
    "step_7": {
      "action": "Click 'Add webhook'"
    }
  },
  "test_configuration": {
    "description": "Test your webhook configuration",
    "curl_command": "curl -X POST \"https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456\" \\\n  -H \"Content-Type: application/json\" \\\n  -H \"X-Hub-Signature-256: sha256=<signature>\" \\\n  -H \"X-GitHub-Event: workflow_run\" \\\n  -d '{\"action\":\"completed\",\"workflow_run\":{\"conclusion\":\"failure\"}}'",
    "generate_test_signature": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/secret/test/me"
  }
}
```

---

### 2. Get Webhook Configuration Info

**Endpoint:** `GET /api/v1/webhook/secret/info/me`

**Description:** Retrieve the current webhook configuration for the authenticated user.

**Authentication:** Required (Bearer token)

**Request Headers:**
```
Authorization: Bearer <your_access_token>
```

**Request Body:** None

**Response:** `200 OK`

**When Secret is Configured:**
```json
{
  "user": {
    "user_id": "dev_abc123xyz456",
    "email": "user@example.com",
    "full_name": "John Doe"
  },
  "webhook_configuration": {
    "secret_configured": true,
    "secret_preview": "xyzA...G890",
    "secret_length": 64,
    "webhook_url": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456",
    "last_updated": "2025-12-13T20:30:00.000000Z"
  },
  "github_settings": {
    "payload_url": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456",
    "content_type": "application/json",
    "events": ["workflow_run", "check_run"],
    "ssl_verification": "enabled"
  },
  "status": {
    "ready": true,
    "message": "Webhook configured and ready"
  },
  "actions": {
    "generate_new_secret": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/secret/generate/me",
    "test_signature": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/secret/test/me",
    "webhook_endpoint": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456"
  }
}
```

**When Secret is NOT Configured:**
```json
{
  "user": {
    "user_id": "dev_abc123xyz456",
    "email": "user@example.com",
    "full_name": "John Doe"
  },
  "webhook_configuration": {
    "secret_configured": false,
    "secret_preview": null,
    "secret_length": 0,
    "webhook_url": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456",
    "last_updated": null
  },
  "github_settings": {
    "payload_url": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456",
    "content_type": "application/json",
    "events": ["workflow_run", "check_run"],
    "ssl_verification": "enabled"
  },
  "status": {
    "ready": false,
    "message": "No webhook secret configured - generate one first"
  },
  "actions": {
    "generate_new_secret": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/secret/generate/me",
    "test_signature": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/secret/test/me",
    "webhook_endpoint": "https://devflowfix-new-production.up.railway.app/api/v1/webhook/github/dev_abc123xyz456"
  }
}
```
