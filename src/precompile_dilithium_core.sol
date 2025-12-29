// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title Precompile-based Dilithium Core (Bytes-Optimized)
 * @notice Uses EIP-7885 NTT precompiles with bytes-based operations for maximum efficiency
 */

import {PrecompileNTT} from "./precompile_NTT.sol";
import {
    q,
    OMEGA,
    k,
    n,
    GAMMA_1,
    Signature,
    PubKey
} from "./ZKNOX_dilithium_utils.sol";
import {useHintDilithium} from "./ZKNOX_hint.sol";

/**
 * @notice Unpack hint vector h from signature
 * @param hBytes Packed h bytes from signature
 * @return success True if unpacking succeeded
 * @return h Hint matrix (4 x 256)
 */
function precompile_unpack_h(bytes memory hBytes) pure returns (bool success, uint256[][] memory h) {
    require(hBytes.length >= OMEGA + k, "Invalid h bytes length");

    uint256 k_idx = 0;

    h = new uint256[][](k);
    for (uint256 i = 0; i < k; i++) {
        h[i] = new uint256[](n);
        for (uint256 j = 0; j < n; j++) {
            h[i][j] = 0;
        }

        uint256 omegaVal = uint8(hBytes[OMEGA + i]);

        // Check bound on omegaVal
        if (omegaVal < k_idx || omegaVal > OMEGA) {
            return (false, h);
        }

        for (uint256 j = k_idx; j < omegaVal; j++) {
            // Coefficients must be in strictly increasing order
            if (j > k_idx && uint8(hBytes[j]) <= uint8(hBytes[j - 1])) {
                return (false, h);
            }

            // Coefficients must be < n
            uint256 index = uint8(hBytes[j]);
            if (index >= n) {
                return (false, h);
            }

            h[i][index] = 1;
        }

        k_idx = omegaVal;
    }

    // Check extra indices are zero
    for (uint256 j = k_idx; j < OMEGA; j++) {
        if (uint8(hBytes[j]) != 0) {
            return (false, h);
        }
    }

    return (true, h);
}

/**
 * @notice Matrix-vector product for Dilithium using bytes-based precompile operations
 * @dev Operates on compact matrix (A is in NTT domain) and bytes z
 * @param A_compact Compact matrix A (4x4 matrix, each element is 32 words)
 * @param z_bytes NTT(z) as bytes array (4 elements, 1024 bytes each)
 * @return result Matrix-vector product as bytes (4 elements, 1024 bytes each)
 */
function PRECOMPILE_MatVecProductDilithium_Bytes(
    uint256[][][] memory A_compact,
    bytes[] memory z_bytes
) view returns (bytes[] memory result) {
    result = new bytes[](4);

    for (uint256 i = 0; i < 4; i++) {
        // Initialize accumulator with zeros
        bytes memory acc = new bytes(1024);

        for (uint256 j = 0; j < 4; j++) {
            // A[i][j] * z[j] using compact A and bytes z
            bytes memory product = PrecompileNTT.PRECOMPILE_VECMULMOD_BytesCompact(z_bytes[j], A_compact[i][j]);

            // Accumulate: acc += product
            acc = PrecompileNTT.PRECOMPILE_VECADDMOD_Bytes(acc, product);
        }
        result[i] = acc;
    }
}

/**
 * @notice Forward NTT from bytes input
 * @param data Input bytes (1024 bytes)
 * @return result NTT result bytes (1024 bytes)
 */
function _PRECOMPILE_NTTFW_FromBytes(bytes memory data) view returns (bytes memory result) {
    bytes memory input = PrecompileNTT.wrapBytesWithHeader(data);

    (bool success, bytes memory output) = address(0x12).staticcall(input);
    require(success, "NTT_FW precompile failed");

    return output;
}

/**
 * @notice Unpack z directly to bytes format with norm check
 * @dev Combines unpacking and norm validation in single pass
 *      Outputs bytes ready for NTT precompile (1024 bytes per polynomial)
 *      Optimized with assembly to avoid stack-too-deep
 * @param inputBytes Packed z from signature
 * @return valid True if all z coefficients pass norm check
 * @return z_bytes Array of 4 polynomials as bytes (1024 bytes each)
 */
function precompile_unpack_z_to_bytes_with_check(bytes memory inputBytes)
    pure
    returns (bool valid, bytes[4] memory z_bytes)
{
    // Level 2: coeffBits = 18, GAMMA_1 = 2^17
    // Level 3/5: coeffBits = 20, GAMMA_1 = 2^19
    uint256 coeffBits = (GAMMA_1 == (1 << 17)) ? 18 : 20;
    uint256 gamma1_minus_beta = 130994; // GAMMA_1 - tau * eta

    valid = true;

    assembly {
        // inputBytes data pointer
        let inputPtr := add(inputBytes, 32)
        let inputLen := mload(inputBytes)

        // Bit offset tracker
        let bitOffset := 0

        // Process 4 polynomials
        for { let polyIdx := 0 } lt(polyIdx, 4) { polyIdx := add(polyIdx, 1) } {
            // Allocate 1024 bytes for this polynomial
            let polyBytes := mload(0x40)
            mstore(polyBytes, 1024) // length
            mstore(0x40, add(polyBytes, add(32, 1024))) // update free memory pointer

            let polyDataPtr := add(polyBytes, 32)

            // Process 256 coefficients
            for { let coeffIdx := 0 } lt(coeffIdx, 256) { coeffIdx := add(coeffIdx, 1) } {
                // Calculate byte offset and bit position
                let byteOff := shr(3, bitOffset)
                let bitInByte := and(bitOffset, 7)

                // Read up to 4 bytes (enough for 20 bits + 7 bit offset)
                let rawValue := 0
                for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                    let idx := add(byteOff, j)
                    if lt(idx, inputLen) {
                        let b := byte(0, mload(add(inputPtr, idx)))
                        rawValue := or(rawValue, shl(mul(8, j), b))
                    }
                }

                // Extract coefficient
                let coeffMask := sub(shl(coeffBits, 1), 1)
                let alteredCoeff := and(shr(bitInByte, rawValue), coeffMask)

                // Compute actual coefficient: gamma_1 - alteredCoeff (mod q)
                let coeff := 0
                let g1 := 131072 // gamma_1 for level 2
                let qVal := 8380417

                if lt(alteredCoeff, g1) {
                    coeff := sub(g1, alteredCoeff)
                }
                if iszero(lt(alteredCoeff, g1)) {
                    coeff := sub(add(qVal, g1), alteredCoeff)
                }

                // Norm check: |coeff| must be <= gamma1_minus_beta
                // Check if coeff > gamma1_minus_beta AND (q - coeff) > gamma1_minus_beta
                if and(gt(coeff, gamma1_minus_beta), gt(sub(qVal, coeff), gamma1_minus_beta)) {
                    valid := 0
                }

                // Store as big-endian int32
                let outPtr := add(polyDataPtr, mul(coeffIdx, 4))
                mstore8(outPtr, shr(24, coeff))
                mstore8(add(outPtr, 1), shr(16, and(coeff, 0xff0000)))
                mstore8(add(outPtr, 2), shr(8, and(coeff, 0xff00)))
                mstore8(add(outPtr, 3), and(coeff, 0xff))

                // Advance bit offset
                bitOffset := add(bitOffset, coeffBits)
            }

            // Store polynomial bytes in output array
            mstore(add(z_bytes, mul(polyIdx, 32)), polyBytes)
        }
    }
}

/**
 * @notice Core step 1 with bytes-based z output
 * @dev Returns z as bytes[4] instead of uint256[][]
 * @param signature Input signature
 * @return foo True if h unpacking succeeded
 * @return norm_h Number of 1s in h
 * @return h Hint matrix
 * @return z_valid True if z passes norm check
 * @return z_bytes z polynomials as bytes (4 x 1024 bytes)
 */
function precompile_dilithium_core_1_bytes(Signature memory signature)
    pure
    returns (bool foo, uint256 norm_h, uint256[][] memory h, bool z_valid, bytes[4] memory z_bytes)
{
    (foo, h) = precompile_unpack_h(signature.h);

    // Count h norm
    norm_h = 0;
    for (uint256 i = 0; i < 4; i++) {
        for (uint256 j = 0; j < 256; j++) {
            if (h[i][j] == 1) {
                norm_h += 1;
            }
        }
    }

    // Unpack z directly to bytes with norm check
    (z_valid, z_bytes) = precompile_unpack_z_to_bytes_with_check(signature.z);
}

/**
 * @notice Core step 2 with bytes-based z input
 * @dev Takes z as bytes[4] directly, avoiding uint256[][] intermediate
 * @param pk Public key with compact A and t1 (t1 must be NTT(t1 << d))
 * @param z_bytes z polynomials as bytes (4 x 1024 bytes, already unpacked)
 * @param c_compact Challenge c in STANDARD domain (compact, 32 words) - NTT applied inside
 * @param h Hint vector
 * @return w_prime_bytes Packed w_prime for final hash
 */
function precompile_dilithium_core_2_bytes(
    PubKey memory pk,
    bytes[4] memory z_bytes,
    uint256[] memory c_compact,
    uint256[][] memory h
) view returns (bytes memory w_prime_bytes) {
    // 1. NTT(z) - z_bytes already in correct format
    bytes[] memory z_ntt_bytes = new bytes[](4);
    for (uint256 i = 0; i < 4; i++) {
        z_ntt_bytes[i] = _PRECOMPILE_NTTFW_FromBytes(z_bytes[i]);
    }

    // 2. A * NTT(z) using compact A and bytes z
    bytes[] memory Az_bytes = PRECOMPILE_MatVecProductDilithium_Bytes(pk.aHat, z_ntt_bytes);

    // 3. NTT(c), then c * t1 and subtract from Az
    // c_compact is challenge in standard domain (NOT NTT), apply NTT here
    // Note: t1 is already NTT(t1 << d) in compact form
    bytes memory c_bytes = PrecompileNTT.encodeCompactForNTT(c_compact);
    (bool ok, bytes memory c_ntt_output) = address(0x12).staticcall(c_bytes);
    require(ok, "NTT_FW failed for c");

    // Process each polynomial
    uint256[][] memory result = new uint256[][](4);
    for (uint256 i = 0; i < 4; i++) {
        // c * t1[i]
        bytes memory ct1 = PrecompileNTT.PRECOMPILE_VECMULMOD_BytesCompact(c_ntt_output, pk.t1[i]);

        // Az - c*t1
        bytes memory diff = PrecompileNTT.PRECOMPILE_VECSUBMOD_Bytes(Az_bytes[i], ct1);

        // Inverse NTT
        bytes memory inv_result = PrecompileNTT.PRECOMPILE_NTTINV_Bytes(diff);

        // Decode to expanded format for useHint
        result[i] = PrecompileNTT.decodeOutputBytes(inv_result);
    }

    // 4. Apply hint and pack result
    w_prime_bytes = useHintDilithium(h, result);
}
