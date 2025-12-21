#!/bin/bash

# NTT Comparison Test Script
# Compares pure Solidity NTT vs EIP-7885 Precompile NTT
#
# Usage: ./compare_ntt.sh [RPC_URL]

RPC_URL="${1:-http://34.173.116.94:8545}"

# Deployed contract addresses
SOLIDITY_TESTER="0x975B5B74439FE463dd59CBA33A4d88572228DAbd"
PRECOMPILE_TESTER="0x70b91E511BDF8D47458A3A30d6d6Dc2E007dd3d8"

echo "=============================================="
echo "NTT Comparison Test"
echo "=============================================="
echo "RPC: $RPC_URL"
echo "Solidity Tester: $SOLIDITY_TESTER"
echo "Precompile Tester: $PRECOMPILE_TESTER"
echo ""

# Test vector: Simple polynomial [1, 2, 3, 4, 0, 0, ..., 0]
# We'll build a uint256[256] array with first 4 elements non-zero

echo "=== Test 1: Simple NTT Forward ==="
echo "Input: [1, 2, 3, 4, 0, 0, ..., 0]"
echo ""

# Build the input array for cast call
# Format: uint256[] - ABI encoded
# First element is offset (0x20), then length (256), then 256 uint256 values

# Simple test with first 4 non-zero values
INPUT_ARRAY="[1,2,3,4$(printf ',0%.0s' {1..252})]"

echo "Calling Solidity nttForward..."
SOLIDITY_RESULT=$(cast call "$SOLIDITY_TESTER" "nttForward(uint256[])(uint256[])" "$INPUT_ARRAY" --rpc-url "$RPC_URL" 2>&1)
echo "Solidity Result (first 8 elements):"
echo "$SOLIDITY_RESULT" | head -n 8
echo ""

echo "Calling Precompile nttForward..."
PRECOMPILE_RESULT=$(cast call "$PRECOMPILE_TESTER" "nttForward(uint256[])(uint256[])" "$INPUT_ARRAY" --rpc-url "$RPC_URL" 2>&1)
echo "Precompile Result (first 8 elements):"
echo "$PRECOMPILE_RESULT" | head -n 8
echo ""

# Compare results
if [ "$SOLIDITY_RESULT" == "$PRECOMPILE_RESULT" ]; then
    echo "✅ NTT Forward: Results MATCH"
else
    echo "❌ NTT Forward: Results DIFFER"
    echo ""
    echo "Full Solidity Result:"
    echo "$SOLIDITY_RESULT"
    echo ""
    echo "Full Precompile Result:"
    echo "$PRECOMPILE_RESULT"
fi

echo ""
echo "=== Test 2: NTT Round Trip (Forward then Inverse) ==="
echo ""

echo "Calling Solidity nttRoundTrip..."
SOLIDITY_RT=$(cast call "$SOLIDITY_TESTER" "nttRoundTrip(uint256[])(uint256[])" "$INPUT_ARRAY" --rpc-url "$RPC_URL" 2>&1)
echo "Solidity Round Trip (first 8 elements):"
echo "$SOLIDITY_RT" | head -n 8
echo ""

echo "Calling Precompile nttRoundTrip..."
PRECOMPILE_RT=$(cast call "$PRECOMPILE_TESTER" "nttRoundTrip(uint256[])(uint256[])" "$INPUT_ARRAY" --rpc-url "$RPC_URL" 2>&1)
echo "Precompile Round Trip (first 8 elements):"
echo "$PRECOMPILE_RT" | head -n 8
echo ""

echo ""
echo "=== Test 3: VECMULMOD ==="
echo "Input A: [1,2,3,4,0,...], B: [5,6,7,8,0,...]"
echo ""

INPUT_A="[1,2,3,4$(printf ',0%.0s' {1..252})]"
INPUT_B="[5,6,7,8$(printf ',0%.0s' {1..252})]"

echo "Calling Solidity vecMulMod..."
SOLIDITY_MUL=$(cast call "$SOLIDITY_TESTER" "vecMulMod(uint256[],uint256[])(uint256[])" "$INPUT_A" "$INPUT_B" --rpc-url "$RPC_URL" 2>&1)
echo "Solidity VECMULMOD (first 8 elements):"
echo "$SOLIDITY_MUL" | head -n 8
echo ""

echo "Calling Precompile vecMulMod..."
PRECOMPILE_MUL=$(cast call "$PRECOMPILE_TESTER" "vecMulMod(uint256[],uint256[])(uint256[])" "$INPUT_A" "$INPUT_B" --rpc-url "$RPC_URL" 2>&1)
echo "Precompile VECMULMOD (first 8 elements):"
echo "$PRECOMPILE_MUL" | head -n 8
echo ""

if [ "$SOLIDITY_MUL" == "$PRECOMPILE_MUL" ]; then
    echo "✅ VECMULMOD: Results MATCH"
else
    echo "❌ VECMULMOD: Results DIFFER"
fi

echo ""
echo "=== Test 4: VECADDMOD ==="
echo ""

echo "Calling Solidity vecAddMod..."
SOLIDITY_ADD=$(cast call "$SOLIDITY_TESTER" "vecAddMod(uint256[],uint256[])(uint256[])" "$INPUT_A" "$INPUT_B" --rpc-url "$RPC_URL" 2>&1)
echo "Solidity VECADDMOD (first 8 elements):"
echo "$SOLIDITY_ADD" | head -n 8
echo ""

echo "Calling Precompile vecAddMod..."
PRECOMPILE_ADD=$(cast call "$PRECOMPILE_TESTER" "vecAddMod(uint256[],uint256[])(uint256[])" "$INPUT_A" "$INPUT_B" --rpc-url "$RPC_URL" 2>&1)
echo "Precompile VECADDMOD (first 8 elements):"
echo "$PRECOMPILE_ADD" | head -n 8
echo ""

if [ "$SOLIDITY_ADD" == "$PRECOMPILE_ADD" ]; then
    echo "✅ VECADDMOD: Results MATCH"
else
    echo "❌ VECADDMOD: Results DIFFER"
fi

echo ""
echo "=== Test 5: Raw Precompile Call (Debug) ==="
echo ""

echo "Calling encodeForPrecompile to see raw input format..."
ENCODED=$(cast call "$PRECOMPILE_TESTER" "encodeForPrecompile(uint256[])(bytes)" "$INPUT_ARRAY" --rpc-url "$RPC_URL" 2>&1)
echo "Encoded input (first 100 chars): ${ENCODED:0:100}..."
echo ""

echo "Calling rawNttFwCall with encoded input..."
RAW_RESULT=$(cast call "$PRECOMPILE_TESTER" "rawNttFwCall(bytes)(bool,bytes)" "$ENCODED" --rpc-url "$RPC_URL" 2>&1)
echo "Raw precompile result:"
echo "$RAW_RESULT"

echo ""
echo "=============================================="
echo "Test Complete"
echo "=============================================="
