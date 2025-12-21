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
}
