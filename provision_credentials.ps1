param(
    [string]$GatewayUrl = $env:EDON_GATEWAY_URL,
    [string]$ApiToken   = $env:EDON_API_TOKEN,
    [string]$TenantId   = $env:EDON_TENANT_ID
)

if (-not $GatewayUrl) { $GatewayUrl = "http://127.0.0.1:8000" }
if (-not $ApiToken)   { throw "EDON_API_TOKEN is required" }

$headers = @{
    "Content-Type" = "application/json"
    "X-EDON-TOKEN" = $ApiToken
}
if ($TenantId) { $headers["X-Tenant-ID"] = $TenantId }

function Set-Credential {
    param(
        [string]$CredentialId,
        [string]$ToolName,
        [string]$CredentialType,
        [hashtable]$CredentialData
    )
    $body = @{
        credential_id  = $CredentialId
        tool_name      = $ToolName
        credential_type= $CredentialType
        credential_data= $CredentialData
        encrypted      = $false
    } | ConvertTo-Json -Depth 6

    Invoke-RestMethod -Method Post -Uri "$GatewayUrl/credentials/set" -Headers $headers -Body $body | Out-Null
    Write-Host "Saved credential for $ToolName ($CredentialId)"
}

Write-Host "== EDON credential provisioning =="

# Brave Search
if ($env:BRAVE_SEARCH_API_KEY) {
    Set-Credential -CredentialId "brave_search" -ToolName "brave_search" -CredentialType "api_key" -CredentialData @{
        api_key = $env:BRAVE_SEARCH_API_KEY
    }
}

# ElevenLabs
if ($env:ELEVENLABS_API_KEY) {
    Set-Credential -CredentialId "elevenlabs" -ToolName "elevenlabs" -CredentialType "api_key" -CredentialData @{
        api_key = $env:ELEVENLABS_API_KEY
    }
}

# GitHub
if ($env:GITHUB_TOKEN) {
    Set-Credential -CredentialId "github" -ToolName "github" -CredentialType "token" -CredentialData @{
        token = $env:GITHUB_TOKEN
    }
}

# Gmail (OAuth refresh supported)
if ($env:GMAIL_ACCESS_TOKEN -or $env:GMAIL_REFRESH_TOKEN) {
    $data = @{
        access_token = $env:GMAIL_ACCESS_TOKEN
        refresh_token = $env:GMAIL_REFRESH_TOKEN
        client_id = $env:GMAIL_CLIENT_ID
        client_secret = $env:GMAIL_CLIENT_SECRET
        token_uri = $(if ($env:GMAIL_TOKEN_URI) { $env:GMAIL_TOKEN_URI } else { "https://oauth2.googleapis.com/token" })
    }
    if ($env:GMAIL_EXPIRES_AT) { $data["expires_at"] = [int]$env:GMAIL_EXPIRES_AT }
    Set-Credential -CredentialId "gmail" -ToolName "gmail" -CredentialType "oauth" -CredentialData $data
}

# Google Calendar (OAuth refresh supported)
if ($env:GOOGLE_CALENDAR_ACCESS_TOKEN -or $env:GOOGLE_CALENDAR_REFRESH_TOKEN) {
    $data = @{
        access_token = $env:GOOGLE_CALENDAR_ACCESS_TOKEN
        refresh_token = $env:GOOGLE_CALENDAR_REFRESH_TOKEN
        client_id = $env:GOOGLE_CALENDAR_CLIENT_ID
        client_secret = $env:GOOGLE_CALENDAR_CLIENT_SECRET
        token_uri = $(if ($env:GOOGLE_CALENDAR_TOKEN_URI) { $env:GOOGLE_CALENDAR_TOKEN_URI } else { "https://oauth2.googleapis.com/token" })
        calendar_id = $(if ($env:GOOGLE_CALENDAR_ID) { $env:GOOGLE_CALENDAR_ID } else { "primary" })
    }
    if ($env:GOOGLE_CALENDAR_EXPIRES_AT) { $data["expires_at"] = [int]$env:GOOGLE_CALENDAR_EXPIRES_AT }
    Set-Credential -CredentialId "google_calendar" -ToolName "google_calendar" -CredentialType "oauth" -CredentialData $data
}

# Clawdbot integration (tenant-scoped via /integrations/clawdbot/connect)
if ($env:CLAWDBOT_GATEWAY_URL -and $env:CLAWDBOT_GATEWAY_TOKEN) {
    $body = @{
        base_url     = $env:CLAWDBOT_GATEWAY_URL
        auth_mode    = "token"
        secret       = $env:CLAWDBOT_GATEWAY_TOKEN
        credential_id= $(if ($env:EDON_CLAWDBOT_CREDENTIAL_ID) { $env:EDON_CLAWDBOT_CREDENTIAL_ID } else { "clawdbot_gateway" })
        probe        = $false
    } | ConvertTo-Json -Depth 4
    Invoke-RestMethod -Method Post -Uri "$GatewayUrl/integrations/clawdbot/connect" -Headers $headers -Body $body | Out-Null
    Write-Host "Connected Clawdbot integration for tenant."
}

Write-Host "Done."
