#!/usr/bin/env bash
# ==============================================================================
# Ethio-SOAR (Waliya-IR) Database Backup Script
# ==============================================================================
# Creates a verified, compressed, timestamped PostgreSQL backup with SHA-256
# checksum manifest and automated retention management.
# ==============================================================================

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Configuration defaults
BACKUP_DIR="${BACKUP_DIR:-${REPO_ROOT}/backups}"
KEEP_COUNT="${KEEP_COUNT:-10}"
TARGET_DB="${POSTGRES_DB:-waliya_ir}"
DB_USER="${POSTGRES_USER:-waliya_user}"
DB_HOST="${POSTGRES_HOST:-127.0.0.1}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_PASS="${POSTGRES_PASSWORD:-}"
USE_DOCKER="${USE_DOCKER:-auto}"
CONTAINER_NAME="${POSTGRES_CONTAINER:-waliya_postgres}"

# Load credentials from .env if available
if [[ -f "${REPO_ROOT}/.env" ]]; then
    # Safely extract variables without sourcing arbitrary code
    set +e
    ENV_PASS=$(grep -E '^POSTGRES_PASSWORD=' "${REPO_ROOT}/.env" | cut -d '=' -f2- | tr -d '"'\''')
    ENV_USER=$(grep -E '^POSTGRES_USER=' "${REPO_ROOT}/.env" | cut -d '=' -f2- | tr -d '"'\''')
    ENV_DB=$(grep -E '^POSTGRES_DB=' "${REPO_ROOT}/.env" | cut -d '=' -f2- | tr -d '"'\''')
    set -e
    [[ -n "${ENV_PASS}" && -z "${DB_PASS}" ]] && DB_PASS="${ENV_PASS}"
    [[ -n "${ENV_USER}" && "${DB_USER}" == "waliya_user" ]] && DB_USER="${ENV_USER}"
    [[ -n "${ENV_DB}" && "${TARGET_DB}" == "waliya_ir" ]] && TARGET_DB="${ENV_DB}"
fi
DB_PASS="${DB_PASS:-waliya_dev_password}"

# Parse optional command-line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            BACKUP_DIR="$2"
            shift 2
            ;;
        --db-name)
            TARGET_DB="$2"
            shift 2
            ;;
        --keep)
            KEEP_COUNT="$2"
            shift 2
            ;;
        --docker)
            USE_DOCKER="true"
            shift
            ;;
        --host)
            USE_DOCKER="false"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --output-dir DIR   Directory to store backups (default: ./backups)"
            echo "  --db-name NAME     Database to backup (default: waliya_ir)"
            echo "  --keep COUNT       Number of recent backups to retain (default: 10)"
            echo "  --docker           Force execution via Docker container"
            echo "  --host             Force execution via host pg_dump"
            echo "  --help, -h         Show this help message"
            exit 0
            ;;
        *)
            echo "[-] Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
BACKUP_FILENAME="${TARGET_DB}_backup_${TIMESTAMP}.dump"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_FILENAME}"
META_PATH="${BACKUP_DIR}/${BACKUP_FILENAME}.meta.json"

echo "[*] Initializing Ethio-SOAR PostgreSQL backup..."
echo "[*] Target Database : ${TARGET_DB}"
echo "[*] Output Path     : ${BACKUP_PATH}"

# Determine execution mode (prefer container pg_dump if container running to match server version)
EXEC_MODE="host"
if [[ "${USE_DOCKER}" == "true" ]]; then
    EXEC_MODE="docker"
elif [[ "${USE_DOCKER}" == "auto" ]]; then
    if [[ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null || true)" == "true" ]]; then
        EXEC_MODE="docker"
    elif ! command -v pg_dump >/dev/null 2>&1; then
        EXEC_MODE="docker"
    fi
fi

# Execute pg_dump
TEMP_BACKUP="${BACKUP_PATH}.tmp"
rm -f "${TEMP_BACKUP}"

DUMP_VERSION=""
ALEMBIC_REV="unknown"

if [[ "${EXEC_MODE}" == "docker" ]]; then
    echo "[*] Running pg_dump inside container '${CONTAINER_NAME}'..."
    DUMP_VERSION=$(docker exec "${CONTAINER_NAME}" pg_dump --version 2>/dev/null || echo "PostgreSQL (container)")

    # Retrieve current alembic revision
    ALEMBIC_REV=$(docker exec -e PGPASSWORD="${DB_PASS}" "${CONTAINER_NAME}" \
        psql -U "${DB_USER}" -d "${TARGET_DB}" -tAc "SELECT version_num FROM alembic_version LIMIT 1;" 2>/dev/null || echo "unknown")

    # Run pg_dump via container stream
    if ! docker exec -e PGPASSWORD="${DB_PASS}" "${CONTAINER_NAME}" \
        pg_dump -U "${DB_USER}" -d "${TARGET_DB}" -Fc --no-owner --no-privileges > "${TEMP_BACKUP}"; then
        echo "[-] ERROR: Container pg_dump failed." >&2
        rm -f "${TEMP_BACKUP}"
        exit 1
    fi
else
    echo "[*] Running pg_dump on host (${DB_HOST}:${DB_PORT})..."
    DUMP_VERSION=$(pg_dump --version)

    # Retrieve current alembic revision
    ALEMBIC_REV=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TARGET_DB}" \
        -tAc "SELECT version_num FROM alembic_version LIMIT 1;" 2>/dev/null || echo "unknown")

    # Run host pg_dump
    if ! PGPASSWORD="${DB_PASS}" pg_dump -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TARGET_DB}" \
        -Fc --no-owner --no-privileges -f "${TEMP_BACKUP}"; then
        echo "[-] ERROR: Host pg_dump failed." >&2
        rm -f "${TEMP_BACKUP}"
        exit 1
    fi
fi

# Verify backup integrity using pg_restore table of contents inspection
echo "[*] Verifying backup archive integrity..."
VERIFIED="false"
if command -v pg_restore >/dev/null 2>&1; then
    if pg_restore --list "${TEMP_BACKUP}" >/dev/null 2>&1; then
        VERIFIED="true"
    fi
elif [[ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null || true)" == "true" ]]; then
    if docker exec -i "${CONTAINER_NAME}" pg_restore --list < "${TEMP_BACKUP}" >/dev/null 2>&1; then
        VERIFIED="true"
    fi
fi

if [[ "${VERIFIED}" != "true" ]]; then
    echo "[-] ERROR: Backup validation failed. Archive is corrupt or incomplete." >&2
    rm -f "${TEMP_BACKUP}"
    exit 1
fi

# Move temporary file to final path and secure permissions
mv "${TEMP_BACKUP}" "${BACKUP_PATH}"
chmod 600 "${BACKUP_PATH}"

BACKUP_SIZE=$(stat -c%s "${BACKUP_PATH}" 2>/dev/null || wc -c < "${BACKUP_PATH}")
SHA256_HASH=$(sha256sum "${BACKUP_PATH}" | awk '{print $1}')

# Generate metadata manifest
cat <<EOF > "${META_PATH}"
{
  "backup_filename": "${BACKUP_FILENAME}",
  "created_at_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "database_name": "${TARGET_DB}",
  "format": "custom (pg_dump -Fc)",
  "size_bytes": ${BACKUP_SIZE},
  "sha256_checksum": "${SHA256_HASH}",
  "alembic_head_revision": "${ALEMBIC_REV}",
  "verification_status": "VERIFIED_VALID",
  "dump_tool_version": "${DUMP_VERSION}"
}
EOF
chmod 600 "${META_PATH}"

echo "[+] Backup created successfully!"
echo "    File:     ${BACKUP_FILENAME}"
echo "    Size:     ${BACKUP_SIZE} bytes"
echo "    SHA-256:  ${SHA256_HASH}"
echo "    Alembic:  ${ALEMBIC_REV}"
echo "    Manifest: ${META_PATH}"

# Retention management: prune older backups exceeding KEEP_COUNT
echo "[*] Applying retention policy (retaining last ${KEEP_COUNT} backups)..."
cd "${BACKUP_DIR}"
# Find .dump files sorted by modification time (oldest first)
DUMP_FILES=( $(ls -1t "${TARGET_DB}_backup_"*.dump 2>/dev/null || true) )
TOTAL_BACKUPS=${#DUMP_FILES[@]}

if [[ ${TOTAL_BACKUPS} -gt ${KEEP_COUNT} ]]; then
    EXCESS=$((TOTAL_BACKUPS - KEEP_COUNT))
    echo "[*] Found ${TOTAL_BACKUPS} backups. Pruning ${EXCESS} oldest backup(s)..."
    for (( i=KEEP_COUNT; i<TOTAL_BACKUPS; i++ )); do
        OLD_DUMP="${DUMP_FILES[$i]}"
        OLD_META="${OLD_DUMP}.meta.json"
        echo "    Pruning: ${OLD_DUMP}"
        rm -f "${OLD_DUMP}" "${OLD_META}"
    done
fi

echo "[SUCCESS] Backup workflow completed."
exit 0
