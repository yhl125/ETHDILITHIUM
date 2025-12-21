#!/bin/bash

# EIP-7885 NTT Precompile Test Script
# Usage: ./test_precompile.sh <RPC_URL>
# Example: ./test_precompile.sh http://localhost:8545

RPC_URL="${1:-http://34.173.116.94:8545}"

echo "Testing NTT Precompiles at: $RPC_URL"
echo "================================================"

# ML-DSA Parameters:
# - ring_degree: 256 (0x00000100)
# - modulus: 8380417 (0x00000000007fe001)

# Test input format:
# [0:4]   ring_degree = 256 (uint32 big-endian)
# [4:12]  modulus = 8380417 (uint64 big-endian)
# [12:*]  coefficients as int32 (4 bytes each, big-endian)

# Simple test: 256 zeros as coefficients
# Header: 00000100 00000000007fe001
# Coefficients: 256 x 00000000 = 1024 bytes of zeros

# Build the input data (header + 256 zero coefficients)
HEADER="0000010000000000007fe001"
ZERO_COEFFS=$(printf '00000000%.0s' {1..256})
INPUT_DATA="0x${HEADER}${ZERO_COEFFS}"

echo ""
echo "1. Testing NTT_FW (address 0x12)"
echo "   Input: ML-DSA params with 256 zero coefficients"
echo ""

RESULT=$(curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"eth_call\",
    \"params\": [{
      \"to\": \"0x0000000000000000000000000000000000000012\",
      \"data\": \"$INPUT_DATA\"
    }, \"latest\"],
    \"id\": 1
  }")

echo "Response: $RESULT"
echo ""

# Check if result contains error
if echo "$RESULT" | grep -q "error"; then
    echo "❌ NTT_FW failed"
else
    echo "✅ NTT_FW responded"
fi

echo ""
echo "2. Testing NTT_INV (address 0x13)"
echo ""

RESULT=$(curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"eth_call\",
    \"params\": [{
      \"to\": \"0x0000000000000000000000000000000000000013\",
      \"data\": \"$INPUT_DATA\"
    }, \"latest\"],
    \"id\": 2
  }")

echo "Response: $RESULT"
echo ""

if echo "$RESULT" | grep -q "error"; then
    echo "❌ NTT_INV failed"
else
    echo "✅ NTT_INV responded"
fi

echo ""
echo "3. Testing NTT_VECMULMOD (address 0x14)"
echo "   Input: Two vectors of 256 zeros each"
echo ""

# VECMULMOD needs two vectors: header + 256 coeffs + 256 coeffs
VEC_INPUT_DATA="0x${HEADER}${ZERO_COEFFS}${ZERO_COEFFS}"

RESULT=$(curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"eth_call\",
    \"params\": [{
      \"to\": \"0x0000000000000000000000000000000000000014\",
      \"data\": \"$VEC_INPUT_DATA\"
    }, \"latest\"],
    \"id\": 3
  }")

echo "Response: $RESULT"
echo ""

if echo "$RESULT" | grep -q "error"; then
    echo "❌ NTT_VECMULMOD failed"
else
    echo "✅ NTT_VECMULMOD responded"
fi

echo ""
echo "4. Testing NTT_VECADDMOD (address 0x15)"
echo ""

RESULT=$(curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"eth_call\",
    \"params\": [{
      \"to\": \"0x0000000000000000000000000000000000000015\",
      \"data\": \"$VEC_INPUT_DATA\"
    }, \"latest\"],
    \"id\": 4
  }")

echo "Response: $RESULT"
echo ""

if echo "$RESULT" | grep -q "error"; then
    echo "❌ NTT_VECADDMOD failed"
else
    echo "✅ NTT_VECADDMOD responded"
fi

echo ""
echo "================================================"
echo "Test Complete"
