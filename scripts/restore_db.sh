#!/usr/bin/env bash
# ==============================================================================
# Ethio-SOAR (Waliya-IR) Safe Database Restore Script
# ==============================================================================
# Validates backup integrity and restores data into an isolated target database
# with strict safeguards against accidental production overwrite.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BACKUP_DIR="${BACKUP_DIR:-${REPO_ROOT}/backups}"
TARGET_DB="${RESTORE_TARGET_DB:-waliya_recovery}"
BACKUP_FILE=""
DB_USER="${POSTGRES_USER:-waliya_user}"
DB_HOST="${POSTGRES_HOST:-127.0.0.1}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_PASS="${POSTGRES_PASSWORD:-}"
FORCE_RESTORE="false"
CONFIRM_PROD="false"
USE_DOCKER="${USE_DOCKER:-auto}"
CONTAINER_NAME="${POSTGRES_CONTAINER:-waliya_postgres}"

# Load credentials from .env if available
if [[ -f "${REPO_ROOT}/.env" ]]; then
    set +e
    ENV_PASS=$(grep -E '^POSTGRES_PASSWORD=' "${REPO_ROOT}/.env" | cut -d '=' -f2- | tr -d '"'\''')
    ENV_USER=$(grep -E '^POSTGRES_USER=' "${REPO_ROOT}/.env" | cut -d '=' -f2- | tr -d '"'\''')
    set -e
    [[ -n "${ENV_PASS}" && -z "${DB_PASS}" ]] && DB_PASS="${ENV_PASS}"
    [[ -n "${ENV_USER}" && "${DB_USER}" == "waliya_user" ]] && DB_USER="${ENV_USER}"
fi
DB_PASS="${DB_PASS:-waliya_dev_password}"

# Parse command line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --backup-file)
            BACKUP_FILE="$2"
            shift 2
            ;;
        --target-db)
            TARGET_DB="$2"
            shift 2
            ;;
        --force)
            FORCE_RESTORE="true"
            shift
            ;;
        --confirm-production-overwrite)
            CONFIRM_PROD="true"
            shift
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
            echo "  --backup-file PATH              Path to .dump backup file (default: latest in ./backups)"
            echo "  --target-db NAME                Target database name (default: waliya_recovery)"
            echo "  --force                         Proceed without confirmation prompts"
            echo "  --confirm-production-overwrite  Required when restoring over live production DB (waliya_ir)"
            echo "  --docker                        Force execution via Docker container"
            echo "  --host                          Force execution via host tools"
            echo "  --help, -h                      Show this help message"
            exit 0
            ;;
        *)
            if [[ -z "${BACKUP_FILE}" && -f "$1" ]]; then
                BACKUP_FILE="$1"
                shift
            else
                echo "[-] Unknown option: $1" >&2
                exit 1
            fi
            ;;
    esac
done

# If backup file was not specified, locate the newest .dump in BACKUP_DIR
if [[ -z "${BACKUP_FILE}" ]]; then
    LATEST_DUMP=$(ls -1t "${BACKUP_DIR}"/*.dump 2>/dev/null | head -n 1 || true)
    if [[ -z "${LATEST_DUMP}" ]]; then
        echo "[-] ERROR: No backup files found in '${BACKUP_DIR}'." >&2
        exit 1
    fi
    BACKUP_FILE="${LATEST_DUMP}"
fi

if [[ ! -f "${BACKUP_FILE}" ]]; then
    echo "[-] ERROR: Backup file '${BACKUP_FILE}' does not exist." >&2
    exit 1
fi

echo "[*] Initializing Ethio-SOAR PostgreSQL restore workflow..."
echo "[*] Backup File     : ${BACKUP_FILE}"
echo "[*] Target Database : ${TARGET_DB}"

# CRITICAL SAFETY GUARD: Prevent accidental production database overwrite
if [[ "${TARGET_DB}" == "waliya_ir" || "${TARGET_DB}" == "production" ]]; then
    echo "[!] WARNING: You have selected the PRIMARY PRODUCTION database '${TARGET_DB}'!" >&2
    if [[ "${CONFIRM_PROD}" != "true" ]]; then
        echo "[-] ERROR: Overwrite of the primary production database requires the" >&2
        echo "    '--confirm-production-overwrite' flag. Operation aborted for safety." >&2
        exit 2
    fi
fi

# Step 1: Checksum Verification against metadata manifest
META_FILE="${BACKUP_FILE}.meta.json"
if [[ -f "${META_FILE}" ]]; then
    echo "[*] Verifying SHA-256 checksum against manifest..."
    EXPECTED_SHA=$(grep -E '"sha256_checksum":' "${META_FILE}" | cut -d '"' -f4)
    ACTUAL_SHA=$(sha256sum "${BACKUP_FILE}" | awk '{print $1}')
    if [[ "${EXPECTED_SHA}" != "${ACTUAL_SHA}" ]]; then
        echo "[-] ERROR: Checksum mismatch! Manifest SHA (${EXPECTED_SHA}) != Actual SHA (${ACTUAL_SHA})." >&2
        echo "    The backup file may be corrupt or tampered with. Aborting restore." >&2
        exit 3
    fi
    echo "[+] Checksum verified: ${ACTUAL_SHA}"
else
    echo "[!] Notice: No metadata manifest found at '${META_FILE}'. Proceeding with direct archive check."
fi

# Step 2: Validate archive structure using pg_restore table-of-contents
echo "[*] Inspecting backup archive table of contents..."
EXEC_MODE="host"
if [[ "${USE_DOCKER}" == "true" ]]; then
    EXEC_MODE="docker"
elif [[ "${USE_DOCKER}" == "auto" ]]; then
    if [[ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null || true)" == "true" ]]; then
        EXEC_MODE="docker"
    elif ! command -v pg_restore >/dev/null 2>&1; then
        EXEC_MODE="docker"
    fi
fi

if [[ "${EXEC_MODE}" == "host" ]]; then
    if ! pg_restore --list "${BACKUP_FILE}" >/dev/null 2>&1; then
        echo "[-] ERROR: Backup archive is invalid or unreadable by pg_restore." >&2
        exit 3
    fi
else
    if ! docker exec -i "${CONTAINER_NAME}" pg_restore --list < "${BACKUP_FILE}" >/dev/null 2>&1; then
        echo "[-] ERROR: Backup archive is invalid or unreadable by container pg_restore." >&2
        exit 3
    fi
fi
echo "[+] Archive structure is valid."

# Step 3: Database creation and connection handling
echo "[*] Ensuring target database '${TARGET_DB}' exists..."

CREATE_DB_SQL="
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname = '${TARGET_DB}') THEN
    PERFORM dblink_exec('', 'CREATE DATABASE ${TARGET_DB} OWNER ${DB_USER}')
    EXCEPTION WHEN undefined_function THEN
      -- dblink not installed; handled by shell script below
      NULL;
  END IF;
END
\$\$;
"

if [[ "${EXEC_MODE}" == "docker" ]]; then
    # Check if target db exists
    DB_EXISTS=$(docker exec -e PGPASSWORD="${DB_PASS}" "${CONTAINER_NAME}" \
        psql -U "${DB_USER}" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${TARGET_DB}'" || echo "0")
    if [[ "${DB_EXISTS}" != "1" ]]; then
        echo "[*] Creating database '${TARGET_DB}' in container..."
        docker exec -e PGPASSWORD="${DB_PASS}" "${CONTAINER_NAME}" \
            psql -U "${DB_USER}" -d postgres -c "CREATE DATABASE ${TARGET_DB} OWNER ${DB_USER};"
    fi
else
    DB_EXISTS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
        -tAc "SELECT 1 FROM pg_database WHERE datname='${TARGET_DB}'" 2>/dev/null || echo "0")
    if [[ "${DB_EXISTS}" != "1" ]]; then
        echo "[*] Creating database '${TARGET_DB}' on host..."
        PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
            -c "CREATE DATABASE ${TARGET_DB} OWNER ${DB_USER};"
    fi
fi

# Step 4: Execute Restoration
echo "[*] Restoring schema and data into '${TARGET_DB}'..."
if [[ "${EXEC_MODE}" == "docker" ]]; then
    # Terminate active connections if overwriting
    docker exec -e PGPASSWORD="${DB_PASS}" "${CONTAINER_NAME}" psql -U "${DB_USER}" -d postgres -c \
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${TARGET_DB}' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true

    # Pipe backup into pg_restore inside container
    set +e
    docker exec -i -e PGPASSWORD="${DB_PASS}" "${CONTAINER_NAME}" \
        pg_restore -U "${DB_USER}" -d "${TARGET_DB}" --clean --if-exists --no-owner --no-privileges < "${BACKUP_FILE}"
    RESTORE_STATUS=$?
    set -e
else
    # Terminate active connections if overwriting
    PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -c \
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${TARGET_DB}' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true

    set +e
    PGPASSWORD="${DB_PASS}" pg_restore -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TARGET_DB}" \
        --clean --if-exists --no-owner --no-privileges "${BACKUP_FILE}"
    RESTORE_STATUS=$?
    set -e
fi

# pg_restore returns 0 for clean success, or 1 for minor warnings (e.g. drop table if exists when clean)
if [[ ${RESTORE_STATUS} -gt 1 ]]; then
    echo "[-] ERROR: pg_restore exited with severe failure code ${RESTORE_STATUS}." >&2
    exit 4
fi

# Step 5: Post-Restore Verification
echo "[*] Performing post-restore validation on '${TARGET_DB}'..."
VERIFY_SQL="
SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';
SELECT version_num FROM alembic_version LIMIT 1;
"

TABLE_COUNT=""
RESTORED_REV=""

if [[ "${EXEC_MODE}" == "docker" ]]; then
    TABLE_COUNT=$(docker exec -e PGPASSWORD="${DB_PASS}" "${CONTAINER_NAME}" \
        psql -U "${DB_USER}" -d "${TARGET_DB}" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';")
    RESTORED_REV=$(docker exec -e PGPASSWORD="${DB_PASS}" "${CONTAINER_NAME}" \
        psql -U "${DB_USER}" -d "${TARGET_DB}" -tAc "SELECT version_num FROM alembic_version LIMIT 1;" 2>/dev/null || echo "MISSING")
else
    TABLE_COUNT=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TARGET_DB}" \
        -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';")
    RESTORED_REV=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TARGET_DB}" \
        -tAc "SELECT version_num FROM alembic_version LIMIT 1;" 2>/dev/null || echo "MISSING")
fi

echo "[+] Target Database Verified:"
echo "    Tables Restored : ${TABLE_COUNT}"
echo "    Alembic Version : ${RESTORED_REV}"

if [[ "${TABLE_COUNT}" -lt 5 || "${RESTORED_REV}" == "MISSING" ]]; then
    echo "[-] ERROR: Post-restore validation failed. Database schema appears incomplete." >&2
    exit 5
fi

echo ""
echo "[SUCCESS] Database restoration completed successfully!"
echo "          Database '${TARGET_DB}' is ready for operational inspection or switchover."
exit 0
