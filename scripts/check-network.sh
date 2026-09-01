#!/bin/bash
# Network Troubleshooting Utility for OWASP Security Workflow
# Tests connectivity to required services and provides remediation steps

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================"
echo "OWASP Security Workflow Network Check"
echo "================================"
echo ""

# Test function
test_connection() {
    local url=$1
    local description=$2
    
    echo -n "Testing $description... "
    
    if curl -s -m 5 --connect-timeout 5 "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ OK${NC}"
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        return 1
    fi
}

# Test required services
echo "REQUIRED Services (workflow will fail if unavailable):"
echo "-----------------------------------------------------"

failed=0

# GitHub
if ! test_connection "https://github.com" "github.com"; then
    ((failed++))
fi

# Container registries
if ! test_connection "https://docker.io" "docker.io (Semgrep container)"; then
    ((failed++))
fi

if ! test_connection "https://ghcr.io" "ghcr.io (ZAP container)"; then
    ((failed++))
fi

echo ""
echo "OPTIONAL Services (fallback if unavailable):"
echo "---------------------------------------------"

# Semgrep
if test_connection "https://semgrep.dev" "semgrep.dev (OWASP rules)"; then
    echo -e "${GREEN}✓${NC} Remote OWASP ruleset available"
else
    echo -e "${YELLOW}⚠${NC} Remote OWASP ruleset unavailable - local config will be used"
fi

echo ""
echo "Summary:"
echo "--------"

if [ $failed -gt 0 ]; then
    echo -e "${RED}✗ FAILED: $failed required service(s) unreachable${NC}"
    echo ""
    echo "Action required:"
    echo "1. Configure firewall rules to allow outbound HTTPS to:"
    echo "   - github.com"
    echo "   - docker.io or registry.hub.docker.com"
    echo "   - ghcr.io"
    echo "2. Verify DNS resolution is working"
    echo "3. Check proxy/VPN configuration"
    exit 1
else
    echo -e "${GREEN}✓ All required services are reachable${NC}"
    echo ""
    echo "If Semgrep still fails with network error:"
    echo "1. Workflow will automatically fall back to local config"
    echo "2. Check GitHub Actions logs for: 'WARNING: Cannot reach semgrep.dev'"
    echo "3. This is expected in air-gapped networks"
    exit 0
fi
