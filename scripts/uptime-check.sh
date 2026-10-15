#!/usr/bin/env bash
# Guardian Uptime Check Script
# Run as a cron job or via external monitoring service (Better Uptime, Pingdom, etc.)

set -euo pipefail

# Configuration
API_URL="${API_URL:-https://api.guardian.example}"
TIMEOUT="${TIMEOUT:-10}"
EXPECTED_VERSION="${EXPECTED_VERSION:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_health() {
    local url="$1"
    local name="$2"
    
    response=$(curl -s -f --max-time "$TIMEOUT" "$url" 2>/dev/null) || {
        echo -e "${RED}FAIL${NC}: $name - Connection failed or timeout"
        return 1
    }
    
    status=$(echo "$response" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")
    version=$(echo "$response" | jq -r '.version // "unknown"' 2>/dev/null || echo "unknown")
    
    if [ "$status" = "healthy" ] || [ "$status" = "ready" ]; then
        if [ -n "$EXPECTED_VERSION" ] && [ "$version" != "$EXPECTED_VERSION" ]; then
            echo -e "${YELLOW}WARN${NC}: $name - Version mismatch (got $version, expected $EXPECTED_VERSION)"
            return 0
        fi
        echo -e "${GREEN}OK${NC}: $name - Status: $status, Version: $version"
        return 0
    else
        echo -e "${RED}FAIL${NC}: $name - Status: $status"
        return 1
    fi
}

# Main checks
echo "Guardian Uptime Check - $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "Target: $API_URL"
echo "---"

FAILURES=0

# Health check
check_health "$API_URL/health" "Health Endpoint" || FAILURES=$((FAILURES + 1))

# Readiness check
check_health "$API_URL/ready" "Readiness Endpoint" || FAILURES=$((FAILURES + 1))

# Quick API test (requires valid device token - skip if not available)
if [ -n "${TEST_DEVICE_TOKEN:-}" ]; then
    echo "---"
    echo "Running authenticated API test..."
    
    # Test analyze endpoint
    response=$(curl -s -f --max-time "$TIMEOUT" \
        -H "Content-Type: application/json" \
        -H "X-Device-Token: $TEST_DEVICE_TOKEN" \
        -d '{"channel": "url", "text": "test", "urls": ["https://example.com"]}' \
        "$API_URL/v1/analyze" 2>/dev/null) || {
        echo -e "${RED}FAIL${NC}: Analyze endpoint - Request failed"
        FAILURES=$((FAILURES + 1))
    }
    
    if [ $? -eq 0 ]; then
        score=$(echo "$response" | jq -r '.score // "null"' 2>/dev/null)
        if [ "$score" != "null" ] && [ -n "$score" ]; then
            echo -e "${GREEN}OK${NC}: Analyze endpoint - Score: $score"
        else
            echo -e "${RED}FAIL${NC}: Analyze endpoint - Invalid response"
            FAILURES=$((FAILURES + 1))
        fi
    fi
fi

# Summary
echo "---"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}All checks passed${NC}"
    exit 0
else
    echo -e "${RED}$FAILURES check(s) failed${NC}"
    exit 1
fi