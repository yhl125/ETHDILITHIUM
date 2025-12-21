// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title Precompile-based Dilithium Core
 * @notice Uses EIP-7885 NTT precompiles instead of pure Solidity NTT implementations
 */

import {console} from "forge-std/Test.sol";

import {PrecompileNTT} from "./precompile_NTT.sol";
import "./ZKNOX_shake.sol";
import {
    q,
    ZKNOX_Expand,
    ZKNOX_Expand_Vec,
    ZKNOX_Expand_Mat,
    bitUnpackAtOffset,
    omega,
    k,
    l,
    n,
    gamma_1,
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
    require(hBytes.length >= omega + k, "Invalid h bytes length");

    uint256 k_idx = 0;

    h = new uint256[][](k);
    for (uint256 i = 0; i < k; i++) {
        h[i] = new uint256[](n);
        for (uint256 j = 0; j < n; j++) {
            h[i][j] = 0;
        }

        uint256 omegaVal = uint8(hBytes[omega + i]);

        // Check bound on omegaVal
        if (omegaVal < k_idx || omegaVal > omega) {
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
    for (uint256 j = k_idx; j < omega; j++) {
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
    if (gamma_1 == (1 << 17)) {
        coeffBits = 18;
        requiredBytes = (n * l * 18) / 8; // Total bytes for all polynomials
    }
    // Level 3 and 5 parameter set
    else if (gamma_1 == (1 << 19)) {
        coeffBits = 20;
        requiredBytes = (n * l * 20) / 8; // Total bytes for all polynomials
    } else {
        revert("gamma_1 must be either 2^17 or 2^19");
    }

    require(inputBytes.length >= requiredBytes, "Insufficient data");

    // Initialize 2D array
    coefficients = new uint256[][](l);

    uint256 bitOffset = 0;

    for (uint256 i = 0; i < l; i++) {
        // Unpack the altered coefficients for polynomial i
        uint256[] memory alteredCoeffs = bitUnpackAtOffset(inputBytes, coeffBits, bitOffset, n);

        // Compute coefficients as gamma_1 - c
        coefficients[i] = new uint256[](n);
        for (uint256 j = 0; j < n; j++) {
            if (alteredCoeffs[j] < gamma_1) {
                coefficients[i][j] = gamma_1 - alteredCoeffs[j];
            } else {
                coefficients[i][j] = q + gamma_1 - alteredCoeffs[j];
            }
        }

        // Move to next polynomial
        bitOffset += n * coeffBits;
    }

    return coefficients;
}

function precompile_dilithium_core_1(Signature memory signature)
    pure
    returns (bool foo, uint256 norm_h, uint256[][] memory h, uint256[][] memory z)
{
    (foo, h) = precompile_unpack_h(signature.h);
    uint256 i;
    uint256 j;
    norm_h = 0;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 256; j++) {
            if (h[i][j] == 1) {
                norm_h += 1;
            }
        }
    }

    z = precompile_unpack_z(signature.z);
}

function precompile_dilithium_core_2(
    PubKey memory pk,
    uint256[][] memory z,
    uint256[] memory c_ntt,
    uint256[][] memory h,
    uint256[][] memory t1_new
) view returns (bytes memory w_prime_bytes) {
    // NTT(z) using precompile
    for (uint256 i = 0; i < 4; i++) {
        z[i] = PrecompileNTT.PRECOMPILE_NTTFW(z[i]);
    }

    // 1. A*z using precompile-based matrix-vector product
    uint256[][][] memory A_hat = ZKNOX_Expand_Mat(pk.a_hat);
    z = PRECOMPILE_MatVecProductDilithium(A_hat, z);

    // 2. A*z - c*t1 using precompile operations
    for (uint256 i = 0; i < 4; i++) {
        // c*t1 using precompile VECMULMOD
        uint256[] memory ct1 = PrecompileNTT.PRECOMPILE_VECMULMOD(t1_new[i], c_ntt);
        // z - c*t1
        uint256[] memory diff = PRECOMPILE_VECSUBMOD(z[i], ct1);
        // Inverse NTT using precompile
        z[i] = PrecompileNTT.PRECOMPILE_NTTINV(diff);
    }

    // 3. w_prime packed using a "solidity-friendly encoding"
    w_prime_bytes = useHintDilithium(h, z);
}
