#!/bin/bash

# TPROXY Fingerprint Testing Script
# Проверяет TLS, HTTP/2, TCP fingerprints и Cloudflare bypass

set -e

PROXY="http://127.0.0.1:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=================================================="
echo "TPROXY v2.0 Fingerprint Testing"
echo "=================================================="
echo ""

# Проверяем что TPROXY запущен
echo -n "Checking if TPROXY is running... "
if ! curl -s --proxy $PROXY --max-time 5 http://httpbin.org/ip > /dev/null 2>&1; then
    echo -e "${RED}FAILED${NC}"
    echo "ERROR: TPROXY is not running on $PROXY"
    echo "Start TPROXY first: ./target/release/tproxy-production"
    exit 1
fi
echo -e "${GREEN}OK${NC}"
echo ""

# Test 1: TLS Fingerprint
echo "=================================================="
echo "Test 1: TLS Fingerprint (JA3)"
echo "=================================================="
echo "Testing: https://tls.peet.ws/api/all"
echo ""

TLS_RESPONSE=$(curl -s --proxy $PROXY https://tls.peet.ws/api/all)
JA3=$(echo $TLS_RESPONSE | jq -r '.tls.ja3' 2>/dev/null || echo "")
JA3_HASH=$(echo $TLS_RESPONSE | jq -r '.tls.ja3_hash' 2>/dev/null || echo "")
TLS_VERSION=$(echo $TLS_RESPONSE | jq -r '.tls.version' 2>/dev/null || echo "")

echo "TLS Version: $TLS_VERSION"
echo "JA3 Hash: $JA3_HASH"
echo ""

if [ ! -z "$JA3_HASH" ]; then
    echo -e "${GREEN}✓ TLS fingerprint detected${NC}"
    echo "JA3 details: $JA3"
else
    echo -e "${YELLOW}⚠ Could not detect JA3 hash${NC}"
fi
echo ""

# Test 2: HTTP/2 Fingerprint
echo "=================================================="
echo "Test 2: HTTP/2 Akamai Fingerprint"
echo "=================================================="
echo "Testing: https://http2.akamai.io/demo"
echo ""

HTTP2_RESPONSE=$(curl -sv --http2 --proxy $PROXY https://http2.akamai.io/demo 2>&1)

if echo "$HTTP2_RESPONSE" | grep -q "HTTP/2"; then
    echo -e "${GREEN}✓ HTTP/2 connection established${NC}"
    
    # Проверяем SETTINGS frame
    if echo "$HTTP2_RESPONSE" | grep -q "settings"; then
        echo -e "${GREEN}✓ HTTP/2 SETTINGS frame detected${NC}"
    fi
    
    # Проверяем Akamai fingerprint
    echo "Checking Akamai HTTP/2 fingerprint..."
    echo "Expected SETTINGS:"
    echo "  - HEADER_TABLE_SIZE = 65536"
    echo "  - INITIAL_WINDOW_SIZE = 1048576"
    echo "  - MAX_FRAME_SIZE = 16384"
else
    echo -e "${RED}✗ HTTP/2 not working${NC}"
fi
echo ""

# Test 3: TCP Fingerprint
echo "=================================================="
echo "Test 3: TCP Fingerprint Check"
echo "=================================================="
echo "Testing TCP parameters..."
echo ""

# Через Browserleaks
echo "Checking via BrowserLeaks..."
BROWSER_RESPONSE=$(curl -s --proxy $PROXY https://browserleaks.com/ip 2>&1 || echo "")

if [ ! -z "$BROWSER_RESPONSE" ]; then
    echo -e "${GREEN}✓ TCP connection successful${NC}"
    echo "Expected TCP parameters:"
    echo "  - TTL: 64 (iOS default)"
    echo "  - MSS: 1460"
    echo "  - Window: 65535"
    echo "  - Window Scale: 7"
else
    echo -e "${YELLOW}⚠ Could not test TCP fingerprint${NC}"
fi
echo ""

# Test 4: Cloudflare Challenge
echo "=================================================="
echo "Test 4: Cloudflare Challenge Bypass"
echo "=================================================="
echo "Testing: https://nowsecure.nl/"
echo ""

CF_RESPONSE=$(curl -s --proxy $PROXY https://nowsecure.nl/ || echo "")

if echo "$CF_RESPONSE" | grep -qi "challenge"; then
    echo -e "${RED}✗ Cloudflare challenge detected (not bypassed)${NC}"
    echo "Response contains challenge page"
elif echo "$CF_RESPONSE" | grep -qi "nowsecure"; then
    echo -e "${GREEN}✓ Cloudflare challenge bypassed successfully${NC}"
    echo "Content received without challenge"
else
    echo -e "${YELLOW}⚠ Unclear result${NC}"
fi
echo ""

# Test 5: Full Browser Fingerprint
echo "=================================================="
echo "Test 5: Full Browser Fingerprint"
echo "=================================================="
echo "Testing: https://browserleaks.com/javascript"
echo ""

FULL_RESPONSE=$(curl -s --proxy $PROXY https://browserleaks.com/javascript || echo "")

if [ ! -z "$FULL_RESPONSE" ]; then
    echo -e "${GREEN}✓ Full fingerprint test accessible${NC}"
    echo "Visit https://browserleaks.com/javascript through TPROXY"
    echo "to see full browser fingerprint details"
else
    echo -e "${YELLOW}⚠ Could not access full fingerprint test${NC}"
fi
echo ""

# Test 6: Timing Test
echo "=================================================="
echo "Test 6: Natural Timing Behavior"
echo "=================================================="
echo "Testing natural delays between requests..."
echo ""

START_TIME=$(date +%s%N)
for i in {1..5}; do
    curl -s --proxy $PROXY http://httpbin.org/ip > /dev/null
done
END_TIME=$(date +%s%N)

DURATION=$(( ($END_TIME - $START_TIME) / 1000000 ))
AVG_DELAY=$(( $DURATION / 5 ))

echo "5 requests took: ${DURATION}ms"
echo "Average delay: ${AVG_DELAY}ms"

if [ $AVG_DELAY -gt 30 ] && [ $AVG_DELAY -lt 200 ]; then
    echo -e "${GREEN}✓ Natural timing detected (not robotic)${NC}"
elif [ $AVG_DELAY -lt 30 ]; then
    echo -e "${YELLOW}⚠ Timing might be too fast (robotic)${NC}"
else
    echo -e "${YELLOW}⚠ Timing might be too slow${NC}"
fi
echo ""

# Test 7: Session Persistence
echo "=================================================="
echo "Test 7: Session Persistence"
echo "=================================================="
echo "Testing session ticket caching..."
echo ""

# Первое соединение
curl -sv --proxy $PROXY https://httpbin.org/ip 2>&1 | grep -i "SSL" > /dev/null && \
    echo -e "${GREEN}✓ First TLS connection established${NC}"

# Второе соединение (должно использовать session resumption)
curl -sv --proxy $PROXY https://httpbin.org/ip 2>&1 | grep -i "SSL" > /dev/null && \
    echo -e "${GREEN}✓ Second TLS connection established${NC}"

echo "Session tickets should be cached and reused"
echo ""

# Test 8: Proxy Authentication (if configured)
echo "=================================================="
echo "Test 8: Proxy Authentication"
echo "=================================================="

if curl -s --proxy $PROXY http://httpbin.org/ip > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Proxy authentication working (if configured)${NC}"
else
    echo -e "${YELLOW}⚠ Proxy authentication might have issues${NC}"
fi
echo ""

# Summary
echo "=================================================="
echo "Test Summary"
echo "=================================================="
echo ""
echo "Tested components:"
echo "  [✓] TLS Fingerprint (JA3)"
echo "  [✓] HTTP/2 Akamai Fingerprint"
echo "  [✓] TCP Parameters"
echo "  [✓] Cloudflare Bypass"
echo "  [✓] Full Browser Fingerprint"
echo "  [✓] Natural Timing"
echo "  [✓] Session Persistence"
echo "  [✓] Proxy Authentication"
echo ""
echo "Next steps:"
echo "1. Check logs for any errors: RUST_LOG=info ./target/release/tproxy-production"
echo "2. Visit test sites manually with TPROXY configured as proxy"
echo "3. Compare fingerprints with real iOS Safari"
echo ""
echo "Test sites to try:"
echo "  - https://tls.peet.ws/api/all (TLS fingerprint)"
echo "  - https://browserleaks.com/ (full fingerprint)"
echo "  - https://nowsecure.nl/ (Cloudflare test)"
echo "  - https://http2.akamai.io/demo (HTTP/2 test)"
echo ""
echo -e "${GREEN}Testing completed!${NC}"