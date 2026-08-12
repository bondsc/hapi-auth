<#
.SYNOPSIS
    Provisions a Microsoft Entra (Azure AD) App Registration for the
    multi-issuer HAPI FHIR auth extension. Cross-platform PowerShell
    equivalent of setup-entra.sh.

.DESCRIPTION
    The same app acts as BOTH the client (machine-to-machine caller) and the
    protected FHIR API resource. After this script completes, the HAPI auth
    wiring is fully usable end-to-end:

        curl -H "Authorization: Bearer <token>" `
             https://drcinterop.<account>.workers.dev/fhir/Patient

    What it does:
      1. Logs in to Azure (if not already)
      2. Generates a self-signed cert + RSA key (openssl)        -> certs/
      3. Creates (or reuses) an Entra App Registration via az
      4. Sets the Application ID URI                              -> ENTRA_AUDIENCE
      5. Defines a 'system.all' app role (allowedMemberTypes=Application)
      6. Uploads the cert; assigns the app role to the app's own SP via Graph
      7. Upserts ENTRA_* keys into ../docker/.env
      8. Prints the Bruno entra environment snippet for copy-paste

    Re-run safely - every step is upsert-style.

.PARAMETER AppDisplayName
    Display name of the Entra app registration. Default: hls-pso-hapi-fhir

.PARAMETER AppRoleName
    Value of the system-wide app role granted to the SP. Default: system.all

.PARAMETER CertDays
    Validity period of the self-signed cert in days. Default: 365

.PARAMETER CertCommonName
    CN used in the self-signed cert subject. Defaults to AppDisplayName.

.PARAMETER Tenancy
    'single' -> AzureADMyOrg (only your tenant can mint tokens for this app).
    'multi'  -> AzureADMultipleOrgs (any Entra tenant whose admin consents).
    Default: multi. Env: TENANCY. Pass -SignInAudience to override the raw value.

.PARAMETER SignInAudience
    Raw Entra signInAudience value. Overrides -Tenancy when provided.
    Env: SIGN_IN_AUDIENCE.

.NOTES
    Requirements: PowerShell 7+, Azure CLI (az), openssl, jq.
    The signed-in user needs Application Administrator (or higher) in the tenant.
#>

[CmdletBinding()]
param(
    [string]$AppDisplayName  = $env:APP_DISPLAY_NAME  ? $env:APP_DISPLAY_NAME  : 'hls-pso-hapi-fhir',
    [string]$AppRoleName     = $env:APP_ROLE_NAME     ? $env:APP_ROLE_NAME     : 'system.all',
    [string]$AppRoleDescription = 'Full HAPI FHIR system-level read/write access',
    [int]   $CertDays        = $(if ($env:CERT_DAYS) { [int]$env:CERT_DAYS } else { 365 }),
    [string]$CertCommonName  = $env:CERT_CN,
    [ValidateSet('single','multi')]
    [string]$Tenancy         = $(if ($env:TENANCY) { $env:TENANCY } else { 'multi' }),
    [string]$SignInAudience  = $env:SIGN_IN_AUDIENCE
)

$ErrorActionPreference = 'Stop'

if (-not $CertCommonName) { $CertCommonName = $AppDisplayName }

if (-not $SignInAudience) {
    $SignInAudience = switch ($Tenancy) {
        'single' { 'AzureADMyOrg' }
        'multi'  { 'AzureADMultipleOrgs' }
    }
}

# ── Paths ─────────────────────────────────────────────────────────────────────
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$HapiAuthDir = Resolve-Path (Join-Path $ScriptDir '..')
$CertsDir    = Join-Path $HapiAuthDir 'certs'
$EnvFile     = Resolve-Path (Join-Path $HapiAuthDir '../docker/.env') -ErrorAction SilentlyContinue
if (-not $EnvFile) {
    $EnvFile = Join-Path $HapiAuthDir '../docker/.env'
}$BrunoEnvFile = Resolve-Path (Join-Path $HapiAuthDir '../bruno-hapi/.env') -ErrorAction SilentlyContinue
if (-not $BrunoEnvFile) {
    $BrunoEnvFile = Join-Path $HapiAuthDir '../bruno-hapi/.env'
}
# ── Sanity checks ─────────────────────────────────────────────────────────────
foreach ($cmd in @('az', 'openssl', 'jq')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "Required command not found: $cmd"
        exit 1
    }
}

# ── Login if needed ───────────────────────────────────────────────────────────
$null = & az account show 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "🔓 Not logged in - launching 'az login'..."
    # --allow-no-subscriptions lets users in tenants without an Azure
    # subscription (e.g. Entra-only directories) still authenticate; the app
    # registration flow we use is Graph-only and does not need a subscription.
    & az login --allow-no-subscriptions --only-show-errors | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "az login failed"
        exit 1
    }
}

$TenantId      = (& az account show --query tenantId -o tsv 2>$null)
$SignedInUser  = (& az account show --query user.name -o tsv 2>$null)
if (-not $TenantId) {
    Write-Error "Could not determine tenant id from 'az account show'"
    exit 1
}
$TenantId     = $TenantId.Trim()
if ($SignedInUser) { $SignedInUser = $SignedInUser.Trim() }

Write-Host "🔐 Tenant:        $TenantId"
Write-Host "👤 Signed in as:  $SignedInUser"
Write-Host "📛 App name:      $AppDisplayName"
Write-Host ""

# ── 1. Generate cert (only if missing) ────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null
$CertPem = Join-Path $CertsDir "$AppDisplayName.cert.pem"
$KeyPem  = Join-Path $CertsDir "$AppDisplayName.key.pem"

if (-not (Test-Path $CertPem) -or -not (Test-Path $KeyPem)) {
    Write-Host "🔑 Generating self-signed cert ($CertDays days, CN=$CertCommonName)..."
    & openssl req -x509 -newkey rsa:2048 -nodes -days $CertDays `
        -keyout $KeyPem -out $CertPem `
        -subj "/CN=$CertCommonName" 2>$null | Out-Null
    if (-not $IsWindows) {
        & chmod 600 $KeyPem
    }
    Write-Host "   -> $CertPem"
    Write-Host "   -> $KeyPem"
} else {
    Write-Host "♻️  Reusing existing cert at $CertPem"
}

# SHA-1 fingerprint, hex (no colons) — needed for Bruno's x5t header.
$fingerprintRaw = & openssl x509 -in $CertPem -fingerprint -sha1 -noout
$CertThumbprintHex = ($fingerprintRaw -replace '.*=', '' -replace ':', '').ToLower()

# ── 2. Create or fetch App Registration ───────────────────────────────────────
$AppId = (& az ad app list --display-name $AppDisplayName --query "[0].appId" -o tsv 2>$null)
if ($AppId) { $AppId = $AppId.Trim() }

if (-not $AppId) {
    Write-Host "📝 Creating app registration '$AppDisplayName' ($SignInAudience)..."
    $AppId = (& az ad app create --display-name $AppDisplayName `
        --sign-in-audience $SignInAudience `
        --query appId -o tsv).Trim()
    Start-Sleep -Seconds 5
} else {
    Write-Host "♻️  Reusing existing app: $AppId"
}

$AppObjectId = (& az ad app show --id $AppId --query id -o tsv).Trim()
$AppIdUri    = "api://$AppId"

# ── 2b. Ensure signInAudience matches the requested tenancy ─────────────────
# AzureADMultipleOrgs lets service principals in OTHER Entra tenants (e.g. a
# Microsoft-internal DCP) authenticate against this app after an admin in that
# tenant consents. Tokens minted in those tenants carry
# iss=login.microsoftonline.com/<thatTenant>/v2.0, so HAPI's HAPI_AUTH_ISSUERS_*
# allow-list must include each partner tenant.
$currentSignInAudience = (& az ad app show --id $AppId --query signInAudience -o tsv 2>$null)
if ($currentSignInAudience) { $currentSignInAudience = $currentSignInAudience.Trim() }
if ($currentSignInAudience -ne $SignInAudience) {
    Write-Host "🌍 Setting signInAudience = $SignInAudience (was '$currentSignInAudience')"
    & az ad app update --id $AppId --sign-in-audience $SignInAudience | Out-Null
}

# ── 3. Set Application ID URI (idempotent) ────────────────────────────────────
$currentUris = (& az ad app show --id $AppId --query identifierUris -o tsv) -split "`t"
if ($currentUris -notcontains $AppIdUri) {
    Write-Host "🌐 Setting identifierUris = $AppIdUri"
    & az ad app update --id $AppId --identifier-uris $AppIdUri | Out-Null
}

# ── 3b. Force v2 access tokens (iss = login.microsoftonline.com/v2.0) ─────────
$currentTokenVer = (& az ad app show --id $AppId --query api.requestedAccessTokenVersion -o tsv 2>$null)
if ($currentTokenVer) { $currentTokenVer = $currentTokenVer.Trim() }
if ($currentTokenVer -ne '2') {
    Write-Host "🔢 Setting api.requestedAccessTokenVersion = 2 (v2 tokens)"
    $body = '{"api":{"requestedAccessTokenVersion":2}}'
    $tmp  = New-TemporaryFile
    Set-Content -Path $tmp -Value $body -Encoding utf8
    & az rest --method PATCH `
        --uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
        --headers Content-Type=application/json `
        --body "@$tmp" | Out-Null
    Remove-Item $tmp
}

# ── 4. Ensure the 'system.all' app role exists ────────────────────────────────
$RoleId = (& az ad app show --id $AppId `
    --query "appRoles[?value=='$AppRoleName'].id | [0]" -o tsv 2>$null)
if ($RoleId) { $RoleId = $RoleId.Trim() }

if (-not $RoleId) {
    Write-Host "🎭 Defining app role '$AppRoleName' (M2M)..."
    $RoleId = [guid]::NewGuid().ToString()
    $rolePayload = @{
        appRoles = @(@{
            id                 = $RoleId
            allowedMemberTypes = @('Application')
            displayName        = $AppRoleName
            description        = $AppRoleDescription
            value              = $AppRoleName
            isEnabled          = $true
        })
    } | ConvertTo-Json -Depth 5 -Compress

    # az rest on Windows wants the body as a file or escaped string; use a temp file.
    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $rolePayload -Encoding utf8
    & az rest --method PATCH `
        --uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
        --headers "Content-Type=application/json" `
        --body "@$tmp" | Out-Null
    Remove-Item $tmp -Force
    Start-Sleep -Seconds 3
} else {
    Write-Host "♻️  App role '$AppRoleName' already defined"
}

# ── 5a. Upload cert to the app (deduped by thumbprint) ────────────────────────
# `az ad app show` returns customKeyIdentifier as the uppercase hex SHA-1
# thumbprint (NOT base64, despite Graph's underlying representation).
$existingThumbprints = & az ad app show --id $AppId `
    --query "keyCredentials[].customKeyIdentifier" -o tsv 2>$null
$existingThumbprintList = @()
if ($existingThumbprints) {
    $existingThumbprintList = $existingThumbprints -split "`n" |
        ForEach-Object { $_.Trim().ToUpper() } |
        Where-Object { $_ }
}
$certThumbUpper = $CertThumbprintHex.ToUpper()

if ($existingThumbprintList -contains $certThumbUpper) {
    Write-Host "♻️  Cert already uploaded to app (thumbprint matches)"
} else {
    Write-Host "📤 Uploading cert to app registration..."
    $years = [Math]::Max(1, [Math]::Ceiling($CertDays / 365.0))
    & az ad app credential reset --id $AppId --cert "@$CertPem" --append --years $years | Out-Null
}

# ── 5a-bis. Ensure a client secret exists (some callers prefer secret over cert) ─
$SecretDisplayName = if ($env:SECRET_DISPLAY_NAME) { $env:SECRET_DISPLAY_NAME } else { 'bruno-hapi' }
$SecretYears      = if ($env:SECRET_YEARS) { [int]$env:SECRET_YEARS } else { 1 }
$existingSecretKid = (& az ad app show --id $AppId `
    --query "passwordCredentials[?displayName=='$SecretDisplayName'] | [0].keyId" `
    -o tsv 2>$null)
if ($existingSecretKid) { $existingSecretKid = $existingSecretKid.Trim() }
$ClientSecret = ''
if ($existingSecretKid) {
    Write-Host "♻️  Client secret '$SecretDisplayName' already exists (keyId=$($existingSecretKid.Substring(0,8))…); leaving unchanged"
    Write-Host "    (delete it in the portal or with 'az ad app credential delete' to rotate)"
} else {
    Write-Host "🔑 Creating client secret '$SecretDisplayName' (valid ${SecretYears}y)..."
    $ClientSecret = (& az ad app credential reset `
        --id $AppId --append `
        --display-name $SecretDisplayName `
        --years $SecretYears `
        --query password -o tsv).Trim()
}

# ── 5b. Ensure service principal exists, then self-assign the app role ───────
$SpId = (& az ad sp list --filter "appId eq '$AppId'" --query "[0].id" -o tsv 2>$null)
if ($SpId) { $SpId = $SpId.Trim() }

if (-not $SpId) {
    Write-Host "🧬 Creating service principal..."
    $SpId = (& az ad sp create --id $AppId --query id -o tsv).Trim()
    Start-Sleep -Seconds 3
}

$existingAssignment = (& az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpId/appRoleAssignedTo" `
    --query "value[?appRoleId=='$RoleId' && principalId=='$SpId'] | [0].id" `
    -o tsv 2>$null)

if (-not $existingAssignment) {
    Write-Host "🎟  Granting app role '$AppRoleName' to the app's own SP..."
    $assignPayload = @{
        principalId = $SpId
        resourceId  = $SpId
        appRoleId   = $RoleId
    } | ConvertTo-Json -Compress
    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $assignPayload -Encoding utf8
    & az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpId/appRoleAssignedTo" `
        --headers "Content-Type=application/json" `
        --body "@$tmp" | Out-Null
    Remove-Item $tmp -Force
} else {
    Write-Host "♻️  App role already assigned to SP"
}

# ── 6. Upsert ENTRA_* keys into src/docker/.env ───────────────────────────────
function Set-EnvVar {
    param([string]$Path, [string]$Key, [string]$Value)
    if (-not (Test-Path $Path)) { New-Item -ItemType File -Path $Path -Force | Out-Null }
    $lines = Get-Content $Path
    $pattern = "^[#\s]*$([Regex]::Escape($Key))="
    if ($lines -match $pattern) {
        $newLines = $lines | ForEach-Object {
            if ($_ -match $pattern) { "$Key=$Value" } else { $_ }
        }
        Set-Content -Path $Path -Value $newLines -Encoding utf8
    } else {
        Add-Content -Path $Path -Value "$Key=$Value"
    }
}

Write-Host "📝 Updating $EnvFile..."
Set-EnvVar -Path $EnvFile -Key 'HAPI_AUTH_ENABLED' -Value 'true'
Set-EnvVar -Path $EnvFile -Key 'ENTRA_TENANT_ID'   -Value $TenantId
# Entra v2 tokens for client_credentials with api://{appId}/.default scope
# carry the bare appId GUID in the `aud` claim (not the api:// URI).
Set-EnvVar -Path $EnvFile -Key 'ENTRA_AUDIENCE'    -Value $AppId
Set-EnvVar -Path $EnvFile -Key 'ENTRA_CLIENT_ID'   -Value $AppId

# ── 6b. Write Bruno collection .env (gitignored) ────────────────────────────
# entra.bru references these via {{process.env.X}}. Bruno's bundled dotenv
# supports multi-line values when wrapped in double quotes.
Write-Host "📝 Writing $BrunoEnvFile..."
$brunoDir = Split-Path -Parent $BrunoEnvFile
if (-not (Test-Path $brunoDir)) { New-Item -ItemType Directory -Force -Path $brunoDir | Out-Null }
# Preserve user-customisable values across re-runs:
#   BRUNO_BASE_URL → may point at a tunnel
#   ENTRA_CLIENT_SECRET → only generated on first run unless rotated
$existingBaseUrl = ''
$existingClientSecret = ''
if (Test-Path $BrunoEnvFile) {
    $m1 = Select-String -Path $BrunoEnvFile -Pattern '^BRUNO_BASE_URL=(.*)$' | Select-Object -First 1
    if ($m1) { $existingBaseUrl = $m1.Matches[0].Groups[1].Value }
    $m2 = Select-String -Path $BrunoEnvFile -Pattern '^ENTRA_CLIENT_SECRET=(.*)$' | Select-Object -First 1
    if ($m2) { $existingClientSecret = $m2.Matches[0].Groups[1].Value }
}
if (-not $existingBaseUrl) { $existingBaseUrl = 'http://hapi-fhir.localhost/fhir' }
$effectiveClientSecret = if ($ClientSecret) { $ClientSecret } else { $existingClientSecret }
$pemContent = Get-Content -Path $KeyPem -Raw
$lines = @(
    '# Auto-generated by setup-entra.ps1 - DO NOT COMMIT (covered by .gitignore).'
    '# Re-running setup-entra.ps1 will overwrite this file (BRUNO_BASE_URL'
    '# and ENTRA_CLIENT_SECRET are preserved if already present).'
    "BRUNO_BASE_URL=$existingBaseUrl"
    "ENTRA_TENANT_ID=$TenantId"
    "ENTRA_CLIENT_ID=$AppId"
    "ENTRA_SCOPE=$AppIdUri/.default"
    "ENTRA_CERT_THUMBPRINT_HEX=$CertThumbprintHex"
    "ENTRA_PRIVATE_KEY_PEM=`"$pemContent`""
)
if ($effectiveClientSecret) {
    $lines += "ENTRA_CLIENT_SECRET=$effectiveClientSecret"
}
$brunoEnvBody = $lines -join "`n"
Set-Content -Path $BrunoEnvFile -Value $brunoEnvBody -Encoding utf8 -NoNewline

# ── 7. Print the Bruno snippet ────────────────────────────────────────────────
Write-Host ""
Write-Host "✅ Done. Recreate HAPI to pick up the new audience:"
Write-Host ""
Write-Host "   cd src/docker"
Write-Host "   docker compose up -d hapi-fhir"
Write-Host ""
Write-Host "The Bruno 'entra' environment now reads everything from bruno-hapi/.env"
Write-Host "(also auto-written, gitignored). Just activate the 'entra' environment"
Write-Host "in Bruno and fire a request."
Write-Host ""
Write-Host "The cert/key live at $CertsDir/ (gitignored - never commit them)."
Write-Host ""
Write-Host "🌍 signInAudience: $SignInAudience"
if ($SignInAudience -eq 'AzureADMultipleOrgs') {
    Write-Host "   Multi-tenant: service principals in OTHER Entra tenants can call this app"
    Write-Host "   after an admin in that tenant grants consent, e.g.:"
    Write-Host "     https://login.microsoftonline.com/<partner-tenant>/adminconsent?client_id=$AppId"
    Write-Host "   Tokens minted in partner tenants carry iss=login.microsoftonline.com/<their-tid>/v2.0,"
    Write-Host "   so add each partner tenant to HAPI's HAPI_AUTH_ISSUERS_* allow-list."
} else {
    Write-Host "   Single-tenant: only identities in $TenantId can obtain tokens for this app."
    Write-Host "   Re-run with -Tenancy multi to allow other Entra tenants to consent."
}
