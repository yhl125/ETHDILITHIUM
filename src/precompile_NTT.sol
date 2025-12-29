// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title Precompile NTT Library for ML-DSA (Dilithium)
 * @notice Wrapper library for EIP-7885 NTT precompiles
 * @dev Precompile addresses:
 *   - NTT_FW:       0x12
 *   - NTT_INV:      0x13
 *   - NTT_VECMULMOD: 0x14
 *   - NTT_VECADDMOD: 0x15
 *
 * Input format for ML-DSA:
 *   - [0:4]   ring_degree = 256 (uint32 big-endian)
 *   - [4:12]  modulus = 8380417 (uint64 big-endian)
 *   - [12:*]  coefficients as int32 (4 bytes each, big-endian)
 *
 * Compact format for Dilithium:
 *   - 32 uint256 words, each containing 8 x 32-bit coefficients
 *   - Coefficients packed as: word = c0 | (c1 << 32) | ... | (c7 << 224)
 */
library PrecompileNTT {
    // Precompile addresses
    address constant NTT_FW_ADDR = address(0x12);
    address constant NTT_INV_ADDR = address(0x13);
    address constant NTT_VECMULMOD_ADDR = address(0x14);
    address constant NTT_VECADDMOD_ADDR = address(0x15);

    // ML-DSA parameters
    uint64 constant MODULUS = 8380417;

    /**
     * @notice Decode precompile output to uint256[] array
     * @dev Precompile returns signed int32 values. Negative values are converted
     *      to their positive modular representation by adding MODULUS.
     * @param data Output bytes from precompile (256 * 4 bytes)
     * @return result Decoded array (256 elements, all positive mod q)
     */
    function decodeOutput(bytes memory data) internal pure returns (uint256[] memory result) {
        require(data.length == 256 * 4, "Invalid output length");

        result = new uint256[](256);
        for (uint256 i = 0; i < 256; i++) {
            uint256 offset = i * 4;
            // Read as uint32 first (big-endian)
            uint32 raw = uint32(uint8(data[offset])) << 24
                       | uint32(uint8(data[offset + 1])) << 16
                       | uint32(uint8(data[offset + 2])) << 8
                       | uint32(uint8(data[offset + 3]));

            // Convert to signed int32 to check if negative
            int32 signedCoeff = int32(raw);

            // Convert to positive modular representation
            if (signedCoeff < 0) {
                // Negative value: add modulus to get positive representation
                result[i] = uint256(int256(signedCoeff) + int256(uint256(MODULUS)));
            } else {
                result[i] = uint256(uint32(signedCoeff));
            }
        }
    }

    /**
     * @notice Encode compact Dilithium polynomial directly to precompile format
     * @dev Compact format: 32 words, 8 coefficients per word (32-bit each)
     * @param compact 32-element array with packed coefficients
     * @return input Encoded bytes for precompile (12-byte header + 1024 bytes data)
     */
    function encodeCompactForNTT(uint256[] memory compact) internal pure returns (bytes memory input) {
        require(compact.length == 32, "Invalid compact length");

        input = new bytes(12 + 1024);

        // Header: ring_degree (4 bytes, big-endian) = 256 = 0x00000100
        input[0] = 0x00;
        input[1] = 0x00;
        input[2] = 0x01;
        input[3] = 0x00;

        // Header: modulus (8 bytes, big-endian) = 8380417 = 0x00000000007FE001
        input[4] = 0x00;
        input[5] = 0x00;
        input[6] = 0x00;
        input[7] = 0x00;
        input[8] = 0x00;
        input[9] = 0x7F;
        input[10] = 0xE0;
        input[11] = 0x01;

        // Extract coefficients from compact format and encode as int32 big-endian
        assembly {
            let inputPtr := add(input, 44) // skip length(32) + header(12)
            let compactPtr := add(compact, 32) // skip length

            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                let word := mload(compactPtr)
                // Extract 8 coefficients (32-bit each) from this word
                for { let j := 0 } lt(j, 8) { j := add(j, 1) } {
                    let coef := and(shr(shl(5, j), word), 0xffffffff)
                    // Store as big-endian int32
                    mstore8(inputPtr, shr(24, coef))
                    mstore8(add(inputPtr, 1), shr(16, and(coef, 0xff0000)))
                    mstore8(add(inputPtr, 2), shr(8, and(coef, 0xff00)))
                    mstore8(add(inputPtr, 3), and(coef, 0xff))
                    inputPtr := add(inputPtr, 4)
                }
                compactPtr := add(compactPtr, 32)
            }
        }
    }

    /**
     * @notice Encode precompile output bytes + compact polynomial for VECOP
     * @param a_bytes Precompile output (1024 bytes)
     * @param b_compact Compact polynomial (32 words)
     * @return input Encoded bytes (12-byte header + 2048 bytes data)
     */
    function encodeBytesCompactVecInput(bytes memory a_bytes, uint256[] memory b_compact)
        internal
        pure
        returns (bytes memory input)
    {
        require(a_bytes.length == 1024, "Invalid a_bytes length");
        require(b_compact.length == 32, "Invalid b_compact length");

        input = new bytes(12 + 2048);

        // Header
        input[0] = 0x00;
        input[1] = 0x00;
        input[2] = 0x01;
        input[3] = 0x00;
        input[4] = 0x00;
        input[5] = 0x00;
        input[6] = 0x00;
        input[7] = 0x00;
        input[8] = 0x00;
        input[9] = 0x7F;
        input[10] = 0xE0;
        input[11] = 0x01;

        assembly {
            let inputPtr := add(input, 44)
            let aPtr := add(a_bytes, 32)

            // Copy a_bytes directly (already in correct format)
            for { let i := 0 } lt(i, 1024) { i := add(i, 32) } {
                mstore(add(inputPtr, i), mload(add(aPtr, i)))
            }
            inputPtr := add(inputPtr, 1024)

            // Encode b_compact
            let bPtr := add(b_compact, 32)
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                let word := mload(bPtr)
                for { let j := 0 } lt(j, 8) { j := add(j, 1) } {
                    let coef := and(shr(shl(5, j), word), 0xffffffff)
                    mstore8(inputPtr, shr(24, coef))
                    mstore8(add(inputPtr, 1), shr(16, and(coef, 0xff0000)))
                    mstore8(add(inputPtr, 2), shr(8, and(coef, 0xff00)))
                    mstore8(add(inputPtr, 3), and(coef, 0xff))
                    inputPtr := add(inputPtr, 4)
                }
                bPtr := add(bPtr, 32)
            }
        }
    }

    /**
     * @notice Encode two precompile output bytes for VECOP
     * @param a_bytes First precompile output (1024 bytes)
     * @param b_bytes Second precompile output (1024 bytes)
     * @return input Encoded bytes (12-byte header + 2048 bytes data)
     */
    function encodeBytesVecInput(bytes memory a_bytes, bytes memory b_bytes)
        internal
        pure
        returns (bytes memory input)
    {
        require(a_bytes.length == 1024 && b_bytes.length == 1024, "Invalid bytes lengths");

        input = new bytes(12 + 2048);

        // Header
        input[0] = 0x00;
        input[1] = 0x00;
        input[2] = 0x01;
        input[3] = 0x00;
        input[4] = 0x00;
        input[5] = 0x00;
        input[6] = 0x00;
        input[7] = 0x00;
        input[8] = 0x00;
        input[9] = 0x7F;
        input[10] = 0xE0;
        input[11] = 0x01;

        assembly {
            let inputPtr := add(input, 44)
            let aPtr := add(a_bytes, 32)
            let bPtr := add(b_bytes, 32)

            // Copy a_bytes
            for { let i := 0 } lt(i, 1024) { i := add(i, 32) } {
                mstore(add(inputPtr, i), mload(add(aPtr, i)))
            }
            inputPtr := add(inputPtr, 1024)

            // Copy b_bytes
            for { let i := 0 } lt(i, 1024) { i := add(i, 32) } {
                mstore(add(inputPtr, i), mload(add(bPtr, i)))
            }
        }
    }

    /**
     * @notice Wrap precompile output bytes with header for next precompile call
     * @param data Precompile output (1024 bytes)
     * @return input Encoded bytes with header (12 + 1024 bytes)
     */
    function wrapBytesWithHeader(bytes memory data) internal pure returns (bytes memory input) {
        require(data.length == 1024, "Invalid data length");

        input = new bytes(12 + 1024);

        // Header
        input[0] = 0x00;
        input[1] = 0x00;
        input[2] = 0x01;
        input[3] = 0x00;
        input[4] = 0x00;
        input[5] = 0x00;
        input[6] = 0x00;
        input[7] = 0x00;
        input[8] = 0x00;
        input[9] = 0x7F;
        input[10] = 0xE0;
        input[11] = 0x01;

        assembly {
            let inputPtr := add(input, 44)
            let dataPtr := add(data, 32)

            for { let i := 0 } lt(i, 1024) { i := add(i, 32) } {
                mstore(add(inputPtr, i), mload(add(dataPtr, i)))
            }
        }
    }

    /**
     * @notice Inverse NTT from bytes input, return raw bytes
     * @param data Precompile input bytes (1024 bytes)
     * @return result Raw precompile output (1024 bytes)
     */
    function PRECOMPILE_NTTINV_Bytes(bytes memory data) internal view returns (bytes memory result) {
        bytes memory input = wrapBytesWithHeader(data);

        (bool success, bytes memory output) = NTT_INV_ADDR.staticcall(input);
        require(success, "NTT_INV precompile failed");

        return output;
    }

    /**
     * @notice Vector multiply: bytes * compact, return raw bytes
     * @param a_bytes First operand as bytes (1024 bytes)
     * @param b_compact Second operand as compact (32 words)
     * @return result Raw precompile output (1024 bytes)
     */
    function PRECOMPILE_VECMULMOD_BytesCompact(bytes memory a_bytes, uint256[] memory b_compact)
        internal
        view
        returns (bytes memory result)
    {
        bytes memory input = encodeBytesCompactVecInput(a_bytes, b_compact);

        (bool success, bytes memory output) = NTT_VECMULMOD_ADDR.staticcall(input);
        require(success, "VECMULMOD precompile failed");

        return output;
    }

    /**
     * @notice Vector add: bytes + bytes, return raw bytes
     * @param a_bytes First operand as bytes (1024 bytes)
     * @param b_bytes Second operand as bytes (1024 bytes)
     * @return result Raw precompile output (1024 bytes)
     */
    function PRECOMPILE_VECADDMOD_Bytes(bytes memory a_bytes, bytes memory b_bytes)
        internal
        view
        returns (bytes memory result)
    {
        bytes memory input = encodeBytesVecInput(a_bytes, b_bytes);

        (bool success, bytes memory output) = NTT_VECADDMOD_ADDR.staticcall(input);
        require(success, "VECADDMOD precompile failed");

        return output;
    }

    /**
     * @notice Vector subtract: bytes - bytes, return raw bytes
     * @dev Implemented as a + (q - b) since no native subtract precompile
     * @param a_bytes First operand as bytes (1024 bytes)
     * @param b_bytes Second operand as bytes (1024 bytes)
     * @return result Raw bytes (1024 bytes)
     */
    function PRECOMPILE_VECSUBMOD_Bytes(bytes memory a_bytes, bytes memory b_bytes)
        internal
        pure
        returns (bytes memory result)
    {
        require(a_bytes.length == 1024 && b_bytes.length == 1024, "Invalid bytes lengths");

        result = new bytes(1024);

        assembly {
            let aPtr := add(a_bytes, 32)
            let bPtr := add(b_bytes, 32)
            let resPtr := add(result, 32)
            let q := 8380417

            for { let i := 0 } lt(i, 256) { i := add(i, 1) } {
                let offset := mul(i, 4)

                // Read a[i] as big-endian int32
                let a_raw := or(
                    or(shl(24, shr(248, mload(add(aPtr, offset)))),
                       shl(16, and(shr(248, mload(add(aPtr, add(offset, 1)))), 0xff))),
                    or(shl(8, and(shr(248, mload(add(aPtr, add(offset, 2)))), 0xff)),
                       and(shr(248, mload(add(aPtr, add(offset, 3)))), 0xff))
                )

                // Read b[i] as big-endian int32
                let b_raw := or(
                    or(shl(24, shr(248, mload(add(bPtr, offset)))),
                       shl(16, and(shr(248, mload(add(bPtr, add(offset, 1)))), 0xff))),
                    or(shl(8, and(shr(248, mload(add(bPtr, add(offset, 2)))), 0xff)),
                       and(shr(248, mload(add(bPtr, add(offset, 3)))), 0xff))
                )

                // Convert from signed to unsigned if negative
                let a_val := a_raw
                if sgt(a_raw, 0x7fffffff) { a_val := add(a_raw, q) }
                let b_val := b_raw
                if sgt(b_raw, 0x7fffffff) { b_val := add(b_raw, q) }

                // Compute (a - b) mod q
                let diff := addmod(a_val, sub(q, mod(b_val, q)), q)

                // Store as big-endian int32
                mstore8(add(resPtr, offset), shr(24, diff))
                mstore8(add(resPtr, add(offset, 1)), shr(16, and(diff, 0xff0000)))
                mstore8(add(resPtr, add(offset, 2)), shr(8, and(diff, 0xff00)))
                mstore8(add(resPtr, add(offset, 3)), and(diff, 0xff))
            }
        }
    }

    /**
     * @notice Decode precompile output bytes to uint256[] array
     * @param data Precompile output (1024 bytes)
     * @return result Decoded array (256 elements)
     */
    function decodeOutputBytes(bytes memory data) internal pure returns (uint256[] memory result) {
        return decodeOutput(data);
    }
}
