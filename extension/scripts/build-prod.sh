#!/usr/bin/env bash
# Production build script for Guardian Chrome Extension
# Usage: ./scripts/build-prod.sh [version]
# Version is read from package.json by default

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTENSION_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$EXTENSION_DIR/dist"
PACKAGE_JSON="$EXTENSION_DIR/package.json"
MANIFEST_JSON="$EXTENSION_DIR/public/manifest.json"

# Read version from package.json or use argument
if [ $# -eq 1 ]; then
    VERSION="$1"
else
    VERSION=$(node -p "require('$PACKAGE_JSON').version")
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Guardian Extension Production Build  ${NC}"
echo -e "${BLUE}  Version: $VERSION${NC}"
echo -e "${BLUE}========================================${NC}"

# Validate version format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
    echo -e "${RED}Error: Invalid version format: $VERSION${NC}"
    echo "Expected format: MAJOR.MINOR.PATCH[-PRERELEASE]"
    exit 1
fi

# Check for required files
if [ ! -f "$PACKAGE_JSON" ]; then
    echo -e "${RED}Error: package.json not found at $PACKAGE_JSON${NC}"
    exit 1
fi

if [ ! -f "$MANIFEST_JSON" ]; then
    echo -e "${RED}Error: manifest.json not found at $MANIFEST_JSON${NC}"
    exit 1
fi

# Check for production API URL
if [ -z "${VITE_API_URL:-}" ]; then
    echo -e "${YELLOW}Warning: VITE_API_URL not set. Using default from vite.config.prod.ts${NC}"
fi

# Step 1: Clean previous build
echo -e "\n${BLUE}[1/6] Cleaning previous build...${NC}"
rm -rf "$DIST_DIR"

# Step 2: Install dependencies
echo -e "\n${BLUE}[2/6] Installing dependencies...${NC}"
cd "$EXTENSION_DIR"
npm ci

# Step 3: Run type checking
echo -e "\n${BLUE}[3/6] Running type check...${NC}"
npm run typecheck

# Step 4: Run linting
echo -e "\n${BLUE}[4/6] Running linter...${NC}"
npm run lint

# Step 5: Build production bundle
echo -e "\n${BLUE}[5/6] Building production bundle...${NC}"
VITE_API_URL="${VITE_API_URL:-https://api.guardian.example}" npm run build:prod

# Step 6: Verify build and create zip
echo -e "\n${BLUE}[6/6] Verifying build and creating zip...${NC}"

# Check that all required files exist
REQUIRED_FILES=(
    "manifest.json"
    "background.js"
    "content.js"
    "popup.html"
    "options.html"
    "blocked.html"
    "analyze-popup.html"
    "icons/icon16.png"
    "icons/icon32.png"
    "icons/icon48.png"
    "icons/icon128.png"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$DIST_DIR/$file" ]; then
        echo -e "${RED}Error: Required file missing: $file${NC}"
        exit 1
    fi
done

# Verify no source maps in dist
if find "$DIST_DIR" -name "*.map" -type f | grep -q .; then
    echo -e "${RED}Error: Source maps found in production build!${NC}"
    find "$DIST_DIR" -name "*.map" -type f
    exit 1
fi

# Verify manifest version matches
MANIFEST_VERSION=$(node -p "require('$DIST_DIR/manifest.json').version")
if [ "$MANIFEST_VERSION" != "$VERSION" ]; then
    echo -e "${RED}Error: Manifest version ($MANIFEST_VERSION) doesn't match package.json ($VERSION)${NC}"
    exit 1
fi

# Verify manifest points to production API
MANIFEST_API=$(node -p "require('$DIST_DIR/manifest.json').host_permissions[0]")
if [[ ! "$MANIFEST_API" =~ ^https://api\.guardian\. ]]; then
    echo -e "${YELLOW}Warning: Manifest host_permissions may not point to production API: $MANIFEST_API${NC}"
fi

# Create production zip
ZIP_NAME="guardian-extension-v${VERSION}.zip"
cd "$DIST_DIR"
zip -r "$ZIP_NAME" . -x "*.map" "*.md" "README*"

# Move zip to extension root for easy access
mv "$ZIP_NAME" "$EXTENSION_DIR/"

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}  Build Successful!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "Version: ${GREEN}$VERSION${NC}"
echo -e "Output:  ${GREEN}$EXTENSION_DIR/$ZIP_NAME${NC}"
echo -e "Dist:    ${GREEN}$DIST_DIR${NC}"
echo -e ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Test the packed extension: chrome://extensions → Load unpacked → select $DIST_DIR"
echo -e "  2. Verify it works against staging API"
echo -e "  3. Submit $ZIP_NAME to Chrome Web Store"
echo -e "  4. Tag the release: git tag v$VERSION && git push origin v$VERSION"