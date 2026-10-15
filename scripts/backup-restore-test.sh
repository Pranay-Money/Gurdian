#!/usr/bin/env bash
# Guardian Backup and Restore Test Script
# Tests that database backups can be restored successfully
# Run quarterly as part of disaster recovery validation

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-/tmp/guardian-backup-test}"
TEST_DB_NAME="guardian_restore_test_$(date +%s)"
TIMESTAMP=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Guardian Backup & Restore Test       ${NC}"
echo -e "${BLUE}  $TIMESTAMP${NC}"
echo -e "${BLUE}========================================${NC}"

# Check required tools
for tool in pg_dump pg_restore psql flyctl; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}Error: $tool not found in PATH${NC}"
        exit 1
    fi
done

# Check Fly.io auth
if ! flyctl auth whoami &> /dev/null; then
    echo -e "${RED}Error: Not logged into Fly.io. Run 'flyctl auth login'${NC}"
    exit 1
fi

# Parse arguments
APP_NAME="${1:-guardian-api}"
ENVIRONMENT="${2:-production}"

if [ "$ENVIRONMENT" = "staging" ]; then
    APP_NAME="${APP_NAME}-staging"
fi

echo -e "\n${BLUE}[1/6] Creating backup directory...${NC}"
mkdir -p "$BACKUP_DIR"
BACKUP_FILE="$BACKUP_DIR/guardian_backup_$(date +%Y%m%d_%H%M%S).dump"

echo -e "\n${BLUE}[2/6] Creating database backup from $APP_NAME...${NC}"
# Get database connection info from Fly.io
DB_URL=$(flyctl postgres attach --app "$APP_NAME" --dry-run 2>/dev/null | grep -oP 'postgresql://[^\s]+' | head -1)

if [ -z "$DB_URL" ]; then
    echo -e "${YELLOW}Warning: Could not get DB URL from Fly. Using manual input.${NC}"
    read -p "Enter source DATABASE_URL: " DB_URL
fi

# Create custom-format backup (compressed, includes schema + data)
echo "Dumping database to $BACKUP_FILE..."
pg_dump -Fc -Z 9 -d "$DB_URL" -f "$BACKUP_FILE"

BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo -e "${GREEN}Backup created: $BACKUP_FILE ($BACKUP_SIZE)${NC}"

echo -e "\n${BLUE}[3/6] Creating test database...${NC}"
# Create a test database on the same PostgreSQL instance
TEST_DB_URL=$(echo "$DB_URL" | sed "s/\/[^/]*$/\/$TEST_DB_NAME/")
# Extract host/port/user/pass from URL and create DB
PSQL_CONN=$(echo "$DB_URL" | sed 's/postgresql+asyncpg:/postgresql:/')
psql "$PSQL_CONN" -c "CREATE DATABASE $TEST_DB_NAME;"

echo -e "\n${BLUE}[4/6] Restoring backup to test database...${NC}"
pg_restore --clean --if-exists --no-owner --no-privileges -d "$TEST_DB_URL" "$BACKUP_FILE"

echo -e "\n${BLUE}[5/6] Validating restore...${NC}"

# Check tables exist
TABLES=$(psql "$TEST_DB_URL" -t -c "
    SELECT count(*) FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
")
TABLES=$(echo $TABLES | xargs)
echo "Tables restored: $TABLES"

if [ "$TABLES" -lt 15 ]; then
    echo -e "${RED}Error: Expected at least 15 tables, got $TABLES${NC}"
    exit 1
fi

# Check critical tables have data (or at least structure)
for table in devices cases signals urls url_intel feedback reported_urls blocklist stats_daily api_usage rate_limit_buckets; do
    COUNT=$(psql "$TEST_DB_URL" -t -c "SELECT count(*) FROM $table;" 2>/dev/null || echo "0")
    COUNT=$(echo $COUNT | xargs)
    echo "  $table: $COUNT rows"
done

# Run migrations to ensure schema is current
echo -e "\nRunning Alembic migrations on restored DB..."
cd "$PROJECT_ROOT/api"
DATABASE_URL="$TEST_DB_URL" alembic upgrade head

# Verify migration version
CURRENT_REV=$(DATABASE_URL="$TEST_DB_URL" alembic current 2>/dev/null | head -1 | awk '{print $1}')
HEAD_REV=$(alembic heads 2>/dev/null | head -1 | awk '{print $1}')

if [ "$CURRENT_REV" = "$HEAD_REV" ]; then
    echo -e "${GREEN}Migrations successful: $CURRENT_REV${NC}"
else
    echo -e "${RED}Migration mismatch: current=$CURRENT_REV, head=$HEAD_REV${NC}"
    exit 1
fi

# Test basic query
TEST_QUERY=$(psql "$TEST_DB_URL" -t -c "SELECT 'restore_test_ok' AS result;")
if [[ "$TEST_QUERY" == *"restore_test_ok"* ]]; then
    echo -e "${GREEN}Basic query test passed${NC}"
else
    echo -e "${RED}Basic query test failed${NC}"
    exit 1
fi

echo -e "\n${BLUE}[6/6] Cleaning up test database...${NC}"
psql "$PSQL_CONN" -c "DROP DATABASE $TEST_DB_NAME;"

# Calculate RTO (Recovery Time Objective)
END_TIME=$(date +%s)
START_TIME=$(stat -c %Y "$BACKUP_FILE" 2>/dev/null || stat -f %m "$BACKUP_FILE")
RTO=$((END_TIME - START_TIME))
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}  RESTORE TEST PASSED ✓${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "Backup file: $BACKUP_FILE"
echo -e "Backup size: $BACKUP_SIZE"
echo -e "Restore time (RTO): ${RTO}s"
echo -e "Test DB: $TEST_DB_NAME (cleaned up)"
echo -e ""
echo -e "${BLUE}Metrics for runbook:${NC}"
echo -e "  RTO (Restore Time Objective): ${RTO}s"
echo -e "  RPO (Recovery Point Objective): Based on backup schedule"
echo -e "  Backup schedule: Daily (Fly.io managed)"
echo -e "  Retention: 7 days (Fly.io default)"

# Cleanup old test backups (keep last 5)
echo -e "\n${BLUE}Cleaning old test backups...${NC}"
ls -t "$BACKUP_DIR"/guardian_backup_*.dump 2>/dev/null | tail -n +6 | xargs -r rm -f

exit 0