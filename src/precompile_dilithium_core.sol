// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title Precompile-based Dilithium Core
 * @notice Uses EIP-7885 NTT precompiles instead of pure Solidity NTT implementations
 */

import {PrecompileNTT} from "./precompile_NTT.sol";
import {
    q,
    expand,
    expandVec,
    expandMat,
    bitUnpackAtOffset,
    OMEGA,
    k,
    l,
    n,
    GAMMA_1,
    Signature,
    PubKey
} from "./ZKNOX_dilithium_utils.sol";
import {useHintDilithium} from "./ZKNOX_hint.sol";

/**
 * @notice Vectorized modular subtraction using precompiles
 * @param a First vector (256 elements)
 * @param b Second vector (256 elements)
 * @return result Element-wise difference (a[i] - b[i] mod q)
 */
function PRECOMPILE_VECSUBMOD(uint256[] memory a, uint256[] memory b) pure returns (uint256[] memory) {
    require(a.length == b.length, "Array lengths must match");
    uint256[] memory res = new uint256[](a.length);
    for (uint256 i = 0; i < a.length; i++) {
        res[i] = addmod(a[i], q - b[i], q);
    }
    return res;
}

/**
 * @notice Matrix-vector product for Dilithium using precompile VECMULMOD
 * @dev Uses precompile-based VECMULMOD for coefficient-wise multiplication
 */
function PRECOMPILE_MatVecProductDilithium(uint256[][][] memory M, uint256[][] memory v)
    view
    returns (uint256[][] memory M_times_v)
{
    uint256 rowCount = 4;
    uint256 colCount = 4;
    uint256 vecSize = 256;

    M_times_v = new uint256[][](rowCount);

    for (uint256 i = 0; i < rowCount; i++) {
        uint256[] memory tmp = new uint256[](vecSize);
        for (uint256 j = 0; j < colCount; j++) {
            uint256[] memory Mij = M[i][j];
            uint256[] memory vj = v[j];

            // Use precompile for vector multiplication
            uint256[] memory product = PrecompileNTT.PRECOMPILE_VECMULMOD(Mij, vj);

            // Accumulate using precompile addition
            tmp = PrecompileNTT.PRECOMPILE_VECADDMOD(tmp, product);
        }
        M_times_v[i] = tmp;
    }
}

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

function precompile_unpack_z(bytes memory inputBytes) pure returns (uint256[][] memory coefficients) {
    uint256 coeffBits;
    uint256 requiredBytes;

    // Level 2 parameter set
    if (GAMMA_1 == (1 << 17)) {
        coeffBits = 18;
        requiredBytes = (n * l * 18) / 8; // Total bytes for all polynomials
    }
    // Level 3 and 5 parameter set
    else if (GAMMA_1 == (1 << 19)) {
        coeffBits = 20;
        requiredBytes = (n * l * 20) / 8; // Total bytes for all polynomials
    } else {
        revert("GAMMA_1 must be either 2^17 or 2^19");
    }

    require(inputBytes.length >= requiredBytes, "Insufficient data");

    // Initialize 2D array
    coefficients = new uint256[][](l);

    uint256 bitOffset = 0;

    for (uint256 i = 0; i < l; i++) {
        // Unpack the altered coefficients for polynomial i
        uint256[] memory alteredCoeffs = bitUnpackAtOffset(inputBytes, coeffBits, bitOffset, n);

        // Compute coefficients as GAMMA_1 - c
        coefficients[i] = new uint256[](n);
        for (uint256 j = 0; j < n; j++) {
            if (alteredCoeffs[j] < GAMMA_1) {
                coefficients[i][j] = GAMMA_1 - alteredCoeffs[j];
            } else {
                coefficients[i][j] = q + GAMMA_1 - alteredCoeffs[j];
            }
        }

        // Move to next polynomial
        bitOffset += n * coeffBits;
    }

    return coefficients;
}

function precompileDilithiumCore1(Signature memory signature)
    pure
    returns (bool foo, uint256 normH, uint256[][] memory h, uint256[][] memory z)
{
    (foo, h) = precompile_unpack_h(signature.h);
    uint256 i;
    uint256 j;
    normH = 0;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 256; j++) {
            if (h[i][j] == 1) {
                normH += 1;
            }
        }
    }

    z = precompile_unpack_z(signature.z);
}

function precompileDilithiumCore2(
    PubKey memory pk,
    uint256[][] memory z,
    uint256[] memory cNtt,
    uint256[][] memory h,
    uint256[][] memory t1New
) view returns (bytes memory wPrimeBytes) {
    // NTT(z) using precompile
    for (uint256 i = 0; i < 4; i++) {
        z[i] = PrecompileNTT.PRECOMPILE_NTTFW(z[i]);
    }

    // 1. A*z using precompile-based matrix-vector product
    uint256[][][] memory A_hat = expandMat(pk.aHat);
    z = PRECOMPILE_MatVecProductDilithium(A_hat, z);

    // 2. A*z - c*t1 using precompile operations
    for (uint256 i = 0; i < 4; i++) {
        // c*t1 using precompile VECMULMOD
        uint256[] memory ct1 = PrecompileNTT.PRECOMPILE_VECMULMOD(t1New[i], cNtt);
        // z - c*t1
        uint256[] memory diff = PRECOMPILE_VECSUBMOD(z[i], ct1);
        // Inverse NTT using precompile
        z[i] = PrecompileNTT.PRECOMPILE_NTTINV(diff);
    }

    // 3. wPrimeBytes packed using a "solidity-friendly encoding"
    wPrimeBytes = useHintDilithium(h, z);
}

// ============================================================================
// OPTIMIZED FUNCTIONS: Bytes-based operations (no expand/compact cycles)
// ============================================================================

/**
 * @notice Matrix-vector product for Dilithium using bytes-based precompile operations
 * @dev Operates on compact matrix (A is in NTT domain) and expanded z
 *      Returns bytes[4] instead of uint256[4][256]
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
 * @notice Optimized Dilithium core step 2 using bytes-based operations
 * @dev Eliminates expand/compact cycles for significant gas savings
 *      Following official Dilithium verification algorithm:
 *      1. NTT(z)
 *      2. w1 = A * NTT(z)
 *      3. NTT(c)
 *      4. t1_shifted = t1 << d
 *      5. NTT(t1_shifted)
 *      6. c * NTT(t1_shifted)
 *      7. w1 - c * t1
 *      8. INTT
 *      9. useHint
 *
 * @param pk Public key with compact A and t1 (t1 must be NTT(t1 << d))
 * @param z Signature z component (expanded, 4 x 256)
 * @param c_compact Challenge c in STANDARD domain (compact, 32 words) - NTT applied inside
 * @param h Hint vector
 * @return w_prime_bytes Packed w_prime for final hash
 */
function precompile_dilithium_core_2_optimized(
    PubKey memory pk,
    uint256[][] memory z,
    uint256[] memory c_compact,
    uint256[][] memory h
) view returns (bytes memory w_prime_bytes) {
    // 1. NTT(z) - keep as bytes for subsequent operations
    bytes[] memory z_ntt_bytes = new bytes[](4);
    for (uint256 i = 0; i < 4; i++) {
        z_ntt_bytes[i] = _encodeExpandedToBytes(z[i]);
        z_ntt_bytes[i] = _PRECOMPILE_NTTFW_FromBytes(z_ntt_bytes[i]);
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

/**
 * @notice Encode expanded polynomial to precompile bytes format
 * @param expanded 256-element expanded array
 * @return result 1024 bytes in precompile format
 */
function _encodeExpandedToBytes(uint256[] memory expanded) pure returns (bytes memory result) {
    require(expanded.length == 256, "Invalid expanded length");

    result = new bytes(1024);

    assembly {
        let resPtr := add(result, 32)
        let expPtr := add(expanded, 32)

        for { let i := 0 } lt(i, 256) { i := add(i, 1) } {
            let coef := mload(expPtr)
            // Store as big-endian int32
            mstore8(resPtr, shr(24, coef))
            mstore8(add(resPtr, 1), shr(16, and(coef, 0xff0000)))
            mstore8(add(resPtr, 2), shr(8, and(coef, 0xff00)))
            mstore8(add(resPtr, 3), and(coef, 0xff))
            resPtr := add(resPtr, 4)
            expPtr := add(expPtr, 32)
        }
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
            // Fixed-size array bytes[4] has no length prefix - elements start at z_bytes directly
            // z_bytes[polyIdx] = polyBytes
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
