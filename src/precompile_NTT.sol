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
    uint32 constant RING_DEGREE = 256;
    uint64 constant MODULUS = 8380417;

    /**
     * @notice Encode a uint256[] array to precompile input format
     * @param a Input array (256 elements, each uint256 representing a coefficient)
     * @return encoded Bytes in precompile format [ring_degree][modulus][coefficients]
     */
    function encodeInput(uint256[] memory a) public pure returns (bytes memory encoded) {
        require(a.length == 256, "Array must have 256 elements");

        encoded = new bytes(12 + 256 * 4);

        // ring_degree (uint32 big-endian)
        encoded[0] = bytes1(uint8(RING_DEGREE >> 24));
        encoded[1] = bytes1(uint8(RING_DEGREE >> 16));
        encoded[2] = bytes1(uint8(RING_DEGREE >> 8));
        encoded[3] = bytes1(uint8(RING_DEGREE));

        // modulus (uint64 big-endian)
        encoded[4] = bytes1(uint8(MODULUS >> 56));
        encoded[5] = bytes1(uint8(MODULUS >> 48));
        encoded[6] = bytes1(uint8(MODULUS >> 40));
        encoded[7] = bytes1(uint8(MODULUS >> 32));
        encoded[8] = bytes1(uint8(MODULUS >> 24));
        encoded[9] = bytes1(uint8(MODULUS >> 16));
        encoded[10] = bytes1(uint8(MODULUS >> 8));
        encoded[11] = bytes1(uint8(MODULUS));

        // coefficients as int32 big-endian
        for (uint256 i = 0; i < 256; i++) {
            uint32 coeff = uint32(a[i]);
            uint256 offset = 12 + i * 4;
            encoded[offset] = bytes1(uint8(coeff >> 24));
            encoded[offset + 1] = bytes1(uint8(coeff >> 16));
            encoded[offset + 2] = bytes1(uint8(coeff >> 8));
            encoded[offset + 3] = bytes1(uint8(coeff));
        }
    }

    /**
     * @notice Encode two uint256[] arrays for vector operations (VECMULMOD, VECADDMOD)
     * @param a First vector (256 elements)
     * @param b Second vector (256 elements)
     * @return encoded Bytes in precompile format [ring_degree][modulus][a coeffs][b coeffs]
     */
    function encodeVecInput(uint256[] memory a, uint256[] memory b) public pure returns (bytes memory encoded) {
        require(a.length == 256 && b.length == 256, "Arrays must have 256 elements");

        encoded = new bytes(12 + 256 * 4 * 2);

        // ring_degree (uint32 big-endian)
        encoded[0] = bytes1(uint8(RING_DEGREE >> 24));
        encoded[1] = bytes1(uint8(RING_DEGREE >> 16));
        encoded[2] = bytes1(uint8(RING_DEGREE >> 8));
        encoded[3] = bytes1(uint8(RING_DEGREE));

        // modulus (uint64 big-endian)
        encoded[4] = bytes1(uint8(MODULUS >> 56));
        encoded[5] = bytes1(uint8(MODULUS >> 48));
        encoded[6] = bytes1(uint8(MODULUS >> 40));
        encoded[7] = bytes1(uint8(MODULUS >> 32));
        encoded[8] = bytes1(uint8(MODULUS >> 24));
        encoded[9] = bytes1(uint8(MODULUS >> 16));
        encoded[10] = bytes1(uint8(MODULUS >> 8));
        encoded[11] = bytes1(uint8(MODULUS));

        // First vector coefficients
        for (uint256 i = 0; i < 256; i++) {
            uint32 coeff = uint32(a[i]);
            uint256 offset = 12 + i * 4;
            encoded[offset] = bytes1(uint8(coeff >> 24));
            encoded[offset + 1] = bytes1(uint8(coeff >> 16));
            encoded[offset + 2] = bytes1(uint8(coeff >> 8));
            encoded[offset + 3] = bytes1(uint8(coeff));
        }

        // Second vector coefficients
        for (uint256 i = 0; i < 256; i++) {
            uint32 coeff = uint32(b[i]);
            uint256 offset = 12 + 256 * 4 + i * 4;
            encoded[offset] = bytes1(uint8(coeff >> 24));
            encoded[offset + 1] = bytes1(uint8(coeff >> 16));
            encoded[offset + 2] = bytes1(uint8(coeff >> 8));
            encoded[offset + 3] = bytes1(uint8(coeff));
        }
    }

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
     * @notice Forward NTT using precompile
     * @param a Input polynomial (256 coefficients)
     * @return NTT-transformed polynomial
     */
    function PRECOMPILE_NTTFW(uint256[] memory a) internal view returns (uint256[] memory) {
        bytes memory input = encodeInput(a);

        (bool success, bytes memory output) = NTT_FW_ADDR.staticcall(input);
        require(success, "NTT_FW precompile call failed");

        return decodeOutput(output);
    }

    /**
     * @notice Inverse NTT using precompile
     * @param a Input polynomial (256 coefficients in NTT domain)
     * @return Inverse NTT-transformed polynomial
     */
    function PRECOMPILE_NTTINV(uint256[] memory a) internal view returns (uint256[] memory) {
        bytes memory input = encodeInput(a);

        (bool success, bytes memory output) = NTT_INV_ADDR.staticcall(input);
        require(success, "NTT_INV precompile call failed");

        return decodeOutput(output);
    }

    /**
     * @notice Vectorized modular multiplication using precompile
     * @param a First vector (256 elements)
     * @param b Second vector (256 elements)
     * @return Element-wise product (a[i] * b[i] mod q)
     */
    function PRECOMPILE_VECMULMOD(uint256[] memory a, uint256[] memory b) internal view returns (uint256[] memory) {
        bytes memory input = encodeVecInput(a, b);

        (bool success, bytes memory output) = NTT_VECMULMOD_ADDR.staticcall(input);
        require(success, "NTT_VECMULMOD precompile call failed");

        return decodeOutput(output);
    }

    /**
     * @notice Vectorized modular addition using precompile
     * @param a First vector (256 elements)
     * @param b Second vector (256 elements)
     * @return Element-wise sum (a[i] + b[i] mod q)
     */
    function PRECOMPILE_VECADDMOD(uint256[] memory a, uint256[] memory b) internal view returns (uint256[] memory) {
        bytes memory input = encodeVecInput(a, b);

        (bool success, bytes memory output) = NTT_VECADDMOD_ADDR.staticcall(input);
        require(success, "NTT_VECADDMOD precompile call failed");

        return decodeOutput(output);
    }

    // ============================================================================
    // OPTIMIZED FUNCTIONS: Direct compact-to-precompile encoding (no expand/compact cycles)
    // ============================================================================

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
     * @notice Encode two compact polynomials for VECMULMOD/VECADDMOD
     * @param a First compact polynomial (32 words)
     * @param b Second compact polynomial (32 words)
     * @return input Encoded bytes (12-byte header + 2048 bytes data)
     */
    function encodeCompactVecInput(uint256[] memory a, uint256[] memory b) internal pure returns (bytes memory input) {
        require(a.length == 32 && b.length == 32, "Invalid compact lengths");

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

            // First polynomial
            let aPtr := add(a, 32)
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                let word := mload(aPtr)
                for { let j := 0 } lt(j, 8) { j := add(j, 1) } {
                    let coef := and(shr(shl(5, j), word), 0xffffffff)
                    mstore8(inputPtr, shr(24, coef))
                    mstore8(add(inputPtr, 1), shr(16, and(coef, 0xff0000)))
                    mstore8(add(inputPtr, 2), shr(8, and(coef, 0xff00)))
                    mstore8(add(inputPtr, 3), and(coef, 0xff))
                    inputPtr := add(inputPtr, 4)
                }
                aPtr := add(aPtr, 32)
            }

            // Second polynomial
            let bPtr := add(b, 32)
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

    // ============================================================================
    // OPTIMIZED PRECOMPILE WRAPPERS: Return bytes instead of decoded arrays
    // ============================================================================

    /**
     * @notice Forward NTT from compact input, return raw bytes
     * @param compact Compact polynomial (32 words)
     * @return result Raw precompile output (1024 bytes)
     */
    function PRECOMPILE_NTTFW_Compact(uint256[] memory compact) internal view returns (bytes memory result) {
        bytes memory input = encodeCompactForNTT(compact);

        (bool success, bytes memory output) = NTT_FW_ADDR.staticcall(input);
        require(success, "NTT_FW precompile failed");

        return output;
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
     * @notice Vector multiply: bytes * bytes, return raw bytes
     * @param a_bytes First operand as bytes (1024 bytes)
     * @param b_bytes Second operand as bytes (1024 bytes)
     * @return result Raw precompile output (1024 bytes)
     */
    function PRECOMPILE_VECMULMOD_Bytes(bytes memory a_bytes, bytes memory b_bytes)
        internal
        view
        returns (bytes memory result)
    {
        bytes memory input = encodeBytesVecInput(a_bytes, b_bytes);

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
