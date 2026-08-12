#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# setup-entra.sh
#
# Idempotently provisions a Microsoft Entra (Azure AD) App Registration suitable
# for the multi-issuer HAPI FHIR auth extension. The same app acts as BOTH the
# client (machine-to-machine caller) and the protected FHIR API resource. After
# this script completes, the HAPI auth wiring is fully usable end-to-end:
#
#   curl -H "Authorization: Bearer <token>" \
#        https://drcinterop.<account>.workers.dev/fhir/Patient
#
# What it does:
#   1. Generates a self-signed cert + RSA key (openssl)        → certs/
#   2. Creates (or reuses) an Entra App Registration via `az`
#   3. Sets the Application ID URI                              → ENTRA_AUDIENCE
#   4. Defines a `system.all` app role (allowedMemberTypes=Application)
#   5. Uploads the cert; assigns the app role to the app's own SP via Graph
#   6. Upserts ENTRA_* keys into ../docker/.env
#   7. Prints the Bruno entra environment snippet for copy-paste
#
# Requirements: az CLI (logged in with App Admin), openssl, jq.
# Re-run safely — every step is upsert-style.
#
# Usage:
#   ./setup-entra.sh                       # multi-tenant (default)
#   TENANCY=single ./setup-entra.sh        # single-tenant (your tenant only)
#   TENANCY=multi  ./setup-entra.sh        # any Entra tenant whose admin consents
#   SIGN_IN_AUDIENCE=AzureADMyOrg ./setup-entra.sh   # raw override
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Config (overridable via env) ──────────────────────────────────────────────
APP_DISPLAY_NAME="${APP_DISPLAY_NAME:-hls-pso-hapi-fhir}"
APP_ROLE_NAME="${APP_ROLE_NAME:-system.all}"
APP_ROLE_DESCRIPTION="${APP_ROLE_DESCRIPTION:-Full HAPI FHIR system-level read/write access}"
CERT_DAYS="${CERT_DAYS:-365}"
CERT_CN="${CERT_CN:-${APP_DISPLAY_NAME}}"
# TENANCY=single|multi   (default: multi)
# Mapped to Entra's signInAudience:
#   single -> AzureADMyOrg          (only your tenant can mint tokens)
#   multi  -> AzureADMultipleOrgs   (any Entra tenant whose admin consents)
# You may also pass SIGN_IN_AUDIENCE directly with any value Entra accepts.
TENANCY="${TENANCY:-multi}"
if [[ -z "${SIGN_IN_AUDIENCE:-}" ]]; then
  case "${TENANCY}" in
    single|SINGLE|AzureADMyOrg)        SIGN_IN_AUDIENCE="AzureADMyOrg" ;;
    multi|MULTI|AzureADMultipleOrgs)   SIGN_IN_AUDIENCE="AzureADMultipleOrgs" ;;
    *) echo "❌ Invalid TENANCY='${TENANCY}'. Use 'single' or 'multi' (or set SIGN_IN_AUDIENCE directly)." >&2; exit 1 ;;
  esac
fi
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
HAPI_AUTH_DIR="$( cd "${SCRIPT_DIR}/.." && pwd )"
CERTS_DIR="${HAPI_AUTH_DIR}/certs"
ENV_FILE="${HAPI_AUTH_DIR}/../docker/.env"
BRUNO_ENV_FILE="${HAPI_AUTH_DIR}/../bruno-hapi/.env"

# ── Sanity checks ─────────────────────────────────────────────────────────────
for cmd in az openssl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "❌ Required command not found: $cmd"
    exit 1
  fi
done

if ! az account show >/dev/null 2>&1; then
  echo "🔓 Not logged in — launching 'az login'..."
  # --allow-no-subscriptions lets users in tenants without an Azure
  # subscription (e.g. Entra-only directories) still authenticate; the app
  # registration flow we use is Graph-only and does not need a subscription.
  if ! az login --allow-no-subscriptions --only-show-errors >/dev/null; then
    echo "❌ az login failed" >&2
    exit 1
  fi
fi

TENANT_ID="$(az account show --query tenantId -o tsv 2>/dev/null)"
SIGNED_IN_USER="$(az account show --query user.name -o tsv 2>/dev/null)"

if [[ -z "${TENANT_ID}" ]]; then
  echo "❌ Could not determine tenant id from 'az account show'" >&2
  exit 1
fi

echo "🔐 Tenant:        ${TENANT_ID}"
echo "👤 Signed in as:  ${SIGNED_IN_USER}"
echo "📛 App name:      ${APP_DISPLAY_NAME}"
echo "🌍 Tenancy:       ${SIGN_IN_AUDIENCE}"
echo

# ── 1. Generate cert (only if missing) ────────────────────────────────────────
mkdir -p "${CERTS_DIR}"
CERT_PEM="${CERTS_DIR}/${APP_DISPLAY_NAME}.cert.pem"
KEY_PEM="${CERTS_DIR}/${APP_DISPLAY_NAME}.key.pem"

if [[ ! -f "${CERT_PEM}" || ! -f "${KEY_PEM}" ]]; then
  echo "🔑 Generating self-signed cert (${CERT_DAYS} days, CN=${CERT_CN})..."
  openssl req -x509 -newkey rsa:2048 -nodes -days "${CERT_DAYS}" \
    -keyout "${KEY_PEM}" -out "${CERT_PEM}" \
    -subj "/CN=${CERT_CN}" >/dev/null 2>&1
  chmod 600 "${KEY_PEM}"
  echo "   → ${CERT_PEM}"
  echo "   → ${KEY_PEM}"
else
  echo "♻️  Reusing existing cert at ${CERT_PEM}"
fi

# SHA-1 fingerprint, hex (no colons) — needed for Bruno's x5t header.
CERT_THUMBPRINT_HEX="$(openssl x509 -in "${CERT_PEM}" -fingerprint -sha1 -noout \
  | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')"

# ── 2. Create or fetch App Registration ───────────────────────────────────────
APP_ID="$(az ad app list --display-name "${APP_DISPLAY_NAME}" --query "[0].appId" -o tsv 2>/dev/null || true)"

if [[ -z "${APP_ID}" ]]; then
  echo "📝 Creating app registration '${APP_DISPLAY_NAME}' (${SIGN_IN_AUDIENCE})..."
  APP_ID="$(az ad app create --display-name "${APP_DISPLAY_NAME}" \
    --sign-in-audience "${SIGN_IN_AUDIENCE}" \
    --query appId -o tsv)"
  # New apps take a few seconds before they're queryable.
  sleep 5
else
  echo "♻️  Reusing existing app: ${APP_ID}"
fi

APP_OBJECT_ID="$(az ad app show --id "${APP_ID}" --query id -o tsv)"
APP_ID_URI="api://${APP_ID}"

# ── 2b. Ensure signInAudience matches the requested tenancy ─────────────────
# AzureADMultipleOrgs lets service principals in OTHER Entra tenants (e.g. a
# Microsoft-internal DCP) authenticate against this app after an admin in that
# tenant consents. Tokens minted in those tenants carry
# iss=login.microsoftonline.com/<thatTenant>/v2.0, so HAPI's HAPI_AUTH_ISSUERS_*
# allow-list must include each partner tenant.
CURRENT_SIGNIN_AUDIENCE="$(az ad app show --id "${APP_ID}" --query signInAudience -o tsv 2>/dev/null || echo "")"
if [[ "${CURRENT_SIGNIN_AUDIENCE}" != "${SIGN_IN_AUDIENCE}" ]]; then
  echo "🌍 Setting signInAudience = ${SIGN_IN_AUDIENCE} (was '${CURRENT_SIGNIN_AUDIENCE}')"
  az ad app update --id "${APP_ID}" --sign-in-audience "${SIGN_IN_AUDIENCE}" >/dev/null
fi

# ── 3. Set Application ID URI (idempotent) ────────────────────────────────────
CURRENT_URIS="$(az ad app show --id "${APP_ID}" --query identifierUris -o tsv || echo "")"
if ! echo "${CURRENT_URIS}" | tr '\t' '\n' | grep -qx "${APP_ID_URI}"; then
  echo "🌐 Setting identifierUris = ${APP_ID_URI}"
  az ad app update --id "${APP_ID}" --identifier-uris "${APP_ID_URI}" >/dev/null
fi
# ── 3b. Force v2 access tokens (iss = login.microsoftonline.com/v2.0) ───────
CURRENT_TOKEN_VER="$(az ad app show --id "${APP_ID}" --query api.requestedAccessTokenVersion -o tsv 2>/dev/null || echo "")"
if [[ "${CURRENT_TOKEN_VER}" != "2" ]]; then
  echo "🔢 Setting api.requestedAccessTokenVersion = 2 (v2 tokens)"
  az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/${APP_OBJECT_ID}" \
    --headers Content-Type=application/json \
    --body '{"api":{"requestedAccessTokenVersion":2}}' >/dev/null
fi
# ── 4. Ensure the `system.all` app role exists ────────────────────────────────
ROLE_ID="$(az ad app show --id "${APP_ID}" \
  --query "appRoles[?value=='${APP_ROLE_NAME}'].id | [0]" -o tsv 2>/dev/null || true)"

if [[ -z "${ROLE_ID}" ]]; then
  echo "🎭 Defining app role '${APP_ROLE_NAME}' (M2M)..."
  ROLE_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  ROLE_PAYLOAD=$(jq -n \
    --arg id "${ROLE_ID}" \
    --arg name "${APP_ROLE_NAME}" \
    --arg desc "${APP_ROLE_DESCRIPTION}" \
    '{
      appRoles: [{
        id: $id,
        allowedMemberTypes: ["Application"],
        displayName: $name,
        description: $desc,
        value: $name,
        isEnabled: true
      }]
    }')
  az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/${APP_OBJECT_ID}" \
    --headers "Content-Type=application/json" \
    --body "${ROLE_PAYLOAD}" >/dev/null
  sleep 3
else
  echo "♻️  App role '${APP_ROLE_NAME}' already defined"
fi

# ── 5a. Upload cert to the app (deduped by thumbprint) ────────────────────────
# `az ad app show` returns customKeyIdentifier as the uppercase hex SHA-1
# thumbprint (NOT base64, despite Graph's underlying representation).
EXISTING_THUMBPRINTS="$(az ad app show --id "${APP_ID}" \
  --query "keyCredentials[].customKeyIdentifier" -o tsv 2>/dev/null \
  | tr '[:lower:]' '[:upper:]' || true)"
CERT_THUMBPRINT_UPPER="$(echo "${CERT_THUMBPRINT_HEX}" | tr '[:lower:]' '[:upper:]')"

if echo "${EXISTING_THUMBPRINTS}" | grep -qx "${CERT_THUMBPRINT_UPPER}"; then
  echo "♻️  Cert already uploaded to app (thumbprint matches)"
else
  echo "📤 Uploading cert to app registration..."
  az ad app credential reset --id "${APP_ID}" --cert "@${CERT_PEM}" \
    --append --years "$(( (CERT_DAYS + 364) / 365 ))" >/dev/null
fi

# ── 5a-bis. Ensure a client secret exists (some callers prefer secret over cert) ─
SECRET_DISPLAY_NAME="${SECRET_DISPLAY_NAME:-bruno-hapi}"
SECRET_YEARS="${SECRET_YEARS:-1}"
EXISTING_SECRET_KID="$(az ad app show --id "${APP_ID}" \
  --query "passwordCredentials[?displayName=='${SECRET_DISPLAY_NAME}'] | [0].keyId" \
  -o tsv 2>/dev/null || true)"
CLIENT_SECRET=""
if [[ -n "${EXISTING_SECRET_KID}" ]]; then
  echo "♻️  Client secret '${SECRET_DISPLAY_NAME}' already exists (keyId=${EXISTING_SECRET_KID:0:8}…); leaving unchanged"
  echo "    (delete it in the portal or with 'az ad app credential delete' to rotate)"
else
  echo "🔑 Creating client secret '${SECRET_DISPLAY_NAME}' (valid ${SECRET_YEARS}y)..."
  CLIENT_SECRET="$(az ad app credential reset \
    --id "${APP_ID}" --append \
    --display-name "${SECRET_DISPLAY_NAME}" \
    --years "${SECRET_YEARS}" \
    --query password -o tsv)"
fi

# ── 5b. Ensure service principal exists, then self-assign the app role ───────
SP_ID="$(az ad sp list --filter "appId eq '${APP_ID}'" --query "[0].id" -o tsv 2>/dev/null || true)"
if [[ -z "${SP_ID}" ]]; then
  echo "🧬 Creating service principal..."
  SP_ID="$(az ad sp create --id "${APP_ID}" --query id -o tsv)"
  sleep 3
fi

EXISTING_ASSIGNMENT="$(az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignedTo" \
  --query "value[?appRoleId=='${ROLE_ID}' && principalId=='${SP_ID}'] | [0].id" \
  -o tsv 2>/dev/null || true)"

if [[ -z "${EXISTING_ASSIGNMENT}" ]]; then
  echo "🎟  Granting app role '${APP_ROLE_NAME}' to the app's own SP..."
  ASSIGN_PAYLOAD=$(jq -n \
    --arg principalId "${SP_ID}" \
    --arg resourceId "${SP_ID}" \
    --arg appRoleId "${ROLE_ID}" \
    '{principalId: $principalId, resourceId: $resourceId, appRoleId: $appRoleId}')
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignedTo" \
    --headers "Content-Type=application/json" \
    --body "${ASSIGN_PAYLOAD}" >/dev/null
else
  echo "♻️  App role already assigned to SP"
fi

# ── 6. Upsert ENTRA_* keys into src/docker/.env ───────────────────────────────
upsert_env() {
  # upsert_env KEY VALUE — adds or replaces KEY=VALUE in ${ENV_FILE}.
  local key="$1" val="$2"
  if [[ ! -f "${ENV_FILE}" ]]; then
    touch "${ENV_FILE}"
  fi
  if grep -qE "^[#[:space:]]*${key}=" "${ENV_FILE}"; then
    # sed -i differs between BSD (macOS) and GNU; use a portable form.
    local tmp; tmp="$(mktemp)"
    awk -v k="${key}" -v v="${val}" '
      BEGIN { FS=OFS="=" }
      $0 ~ "^[#[:space:]]*" k "=" { print k "=" v; next }
      { print }
    ' "${ENV_FILE}" > "${tmp}" && mv "${tmp}" "${ENV_FILE}"
  else
    printf '%s=%s\n' "${key}" "${val}" >> "${ENV_FILE}"
  fi
}

echo "📝 Updating ${ENV_FILE}..."
upsert_env "HAPI_AUTH_ENABLED" "true"
upsert_env "ENTRA_TENANT_ID" "${TENANT_ID}"
# Entra v2 tokens for client_credentials with api://{appId}/.default scope
# carry the bare appId GUID in the `aud` claim (not the api:// URI).
upsert_env "ENTRA_AUDIENCE" "${APP_ID}"
upsert_env "ENTRA_CLIENT_ID" "${APP_ID}"

# ── 6b. Write Bruno collection .env (gitignored) ────────────────────────────
# entra.bru references these via {{process.env.X}}. Bruno's bundled dotenv
# supports multi-line values when wrapped in double quotes, so the PEM goes
# in raw.
echo "📝 Writing ${BRUNO_ENV_FILE}..."
mkdir -p "$(dirname "${BRUNO_ENV_FILE}")"
# Preserve user-customisable values across re-runs:
#   BRUNO_BASE_URL → may point at a tunnel
#   ENTRA_CLIENT_SECRET → only generated on first run unless rotated
EXISTING_BASE_URL=""
EXISTING_CLIENT_SECRET=""
if [[ -f "${BRUNO_ENV_FILE}" ]]; then
  EXISTING_BASE_URL="$(awk -F= '/^BRUNO_BASE_URL=/{sub(/^BRUNO_BASE_URL=/,""); print; exit}' "${BRUNO_ENV_FILE}")"
  EXISTING_CLIENT_SECRET="$(awk -F= '/^ENTRA_CLIENT_SECRET=/{sub(/^ENTRA_CLIENT_SECRET=/,""); print; exit}' "${BRUNO_ENV_FILE}")"
fi
BRUNO_BASE_URL_VALUE="${EXISTING_BASE_URL:-http://hapi-fhir.localhost/fhir}"
EFFECTIVE_CLIENT_SECRET="${CLIENT_SECRET:-${EXISTING_CLIENT_SECRET}}"
{
  echo "# Auto-generated by setup-entra.sh - DO NOT COMMIT (covered by .gitignore)."
  echo "# Re-running setup-entra.sh will overwrite this file (BRUNO_BASE_URL"
  echo "# and ENTRA_CLIENT_SECRET are preserved if already present)."
  echo "BRUNO_BASE_URL=${BRUNO_BASE_URL_VALUE}"
  echo "ENTRA_TENANT_ID=${TENANT_ID}"
  echo "ENTRA_CLIENT_ID=${APP_ID}"
  echo "ENTRA_SCOPE=${APP_ID_URI}/.default"
  echo "ENTRA_CERT_THUMBPRINT_HEX=${CERT_THUMBPRINT_HEX}"
  printf 'ENTRA_PRIVATE_KEY_PEM="'
  cat "${KEY_PEM}"
  printf '"\n'
  if [[ -n "${EFFECTIVE_CLIENT_SECRET}" ]]; then
    echo "ENTRA_CLIENT_SECRET=${EFFECTIVE_CLIENT_SECRET}"
  fi
} > "${BRUNO_ENV_FILE}"
chmod 600 "${BRUNO_ENV_FILE}"

# ── 7. Print the Bruno snippet ────────────────────────────────────────────────
cat <<EOF

✅ Done. Recreate HAPI to pick up the new audience:

   cd $(realpath --relative-to="$(pwd)" "${HAPI_AUTH_DIR}/../docker" 2>/dev/null || echo src/docker)
   docker compose up -d hapi-fhir

The Bruno 'entra' environment now reads everything from bruno-hapi/.env
(also auto-written, gitignored). Just activate the 'entra' environment in
Bruno and fire a request.

The cert/key live at ${CERTS_DIR}/ (gitignored — never commit them).

🌍 signInAudience: ${SIGN_IN_AUDIENCE}
EOF

if [[ "${SIGN_IN_AUDIENCE}" == "AzureADMultipleOrgs" ]]; then
  cat <<EOF
   Multi-tenant: service principals in OTHER Entra tenants can call this app
   after an admin in that tenant grants consent, e.g.:
     https://login.microsoftonline.com/<partner-tenant>/adminconsent?client_id=${APP_ID}
   Tokens minted in partner tenants carry iss=login.microsoftonline.com/<their-tid>/v2.0,
   so add each partner tenant to HAPI's HAPI_AUTH_ISSUERS_* allow-list.
EOF
else
  cat <<EOF
   Single-tenant: only identities in ${TENANT_ID} can obtain tokens for this app.
   Re-run with TENANCY=multi to allow other Entra tenants to consent.
EOF
fi
