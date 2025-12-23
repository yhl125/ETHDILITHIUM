/**
 *
 */
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN        NNNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                         ..../&@&#.       .###%@@@#, ..
/*Z:::::::::::::::::ZK:::::::K    K:::::KN:::::::N       N::::::N   OO:::::::::OO   X:::::X       X:::::X                      ...(@@* .... .           &#//%@@&,.
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::::N      N::::::N OO:::::::::::::OO X:::::X       X:::::X                    ..*@@.........              .@#%%(%&@&..
/*Z:::ZZZZZZZZ:::::Z K:::::::K   K::::::KN:::::::::N     N::::::NO:::::::OOO:::::::OX::::::X     X::::::X                   .*@( ........ .  .&@@@@.      .@%%%%%#&@@.
/*ZZZZZ     Z:::::Z  KK::::::K  K:::::KKKN::::::::::N    N::::::NO::::::O   O::::::OXXX:::::X   X::::::XX                ...&@ ......... .  &.     .@      /@%%%%%%&@@#
/*        Z:::::Z      K:::::K K:::::K   N:::::::::::N   N::::::NO:::::O     O:::::O   X:::::X X:::::X                   ..@( .......... .  &.     ,&      /@%%%%&&&&@@@.
/*       Z:::::Z       K::::::K:::::K    N:::::::N::::N  N::::::NO:::::O     O:::::O    X:::::X:::::X                   ..&% ...........     .@%(#@#      ,@%%%%&&&&&@@@%.
/*      Z:::::Z        K:::::::::::K     N::::::N N::::N N::::::NO:::::O     O:::::O     X:::::::::X                   ..,@ ............                 *@%%%&%&&&&&&@@@.
/*     Z:::::Z         K:::::::::::K     N::::::N  N::::N:::::::NO:::::O     O:::::O     X:::::::::X                  ..(@ .............             ,#@&&&&&&&&&&&&@@@@*
/*    Z:::::Z          K::::::K:::::K    N::::::N   N:::::::::::NO:::::O     O:::::O    X:::::X:::::X                   .*@..............  . ..,(%&@@&&&&&&&&&&&&&&&&@@@@,
/*   Z:::::Z           K:::::K K:::::K   N::::::N    N::::::::::NO:::::O     O:::::O   X:::::X X:::::X                 ...&#............. *@@&&&&&&&&&&&&&&&&&&&&@@&@@@@&
/*ZZZ:::::Z     ZZZZZKK::::::K  K:::::KKKN::::::N     N:::::::::NO::::::O   O::::::OXXX:::::X   X::::::XX               ...@/.......... *@@@@. ,@@.  &@&&&&&&@@@@@@@@@@@.
/*Z::::::ZZZZZZZZ:::ZK:::::::K   K::::::KN::::::N      N::::::::NO:::::::OOO:::::::OX::::::X     X::::::X               ....&#..........@@@, *@@&&&@% .@@@@@@@@@@@@@@@&
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N       N:::::::N OO:::::::::::::OO X:::::X       X:::::X                ....*@.,......,@@@...@@@@@@&..%@@@@@@@@@@@@@/
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N        N::::::N   OO:::::::::OO   X:::::X       X:::::X                   ...*@,,.....%@@@,.........%@@@@@@@@@@@@(
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN         NNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                      ...&@,....*@@@@@ ..,@@@@@@@@@@@@@&.
/*                                                                                                                                   ....,(&@@&..,,,/@&#*. .
/*                                                                                                                                    ......(&.,.,,/&@,.
/*                                                                                                                                      .....,%*.,*@%
/*                                                                                                                                    .#@@@&(&@*,,*@@%,..
/*                                                                                                                                    .##,,,**$.,,*@@@@@%.
/*                                                                                                                                     *(%%&&@(,,**@@@@@&
/*                                                                                                                                      . .  .#@((@@(*,**
/*                                                                                                                                             . (*. .
/*                                                                                                                                              .*/
///* Copyright (C) 2025 - Renaud Dubois, Simon Masson - This file is part of ZKNOX project
///* License: This software is licensed under MIT License
///* This Code may be reused including this header, license and copyright notice.
///* See LICENSE file at the root folder of the project.
///* FILE: precompile_ethdilithium.sol
///* Description: Compute ethereum friendly version of dilithium verification using EIP-7885 NTT precompiles
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {PrecompileNTT} from "./precompile_NTT.sol";
import {
    precompile_dilithium_core_1,
    precompile_dilithium_core_2,
    precompile_dilithium_core_2_optimized,
    precompile_dilithium_core_1_bytes,
    precompile_dilithium_core_2_bytes
} from "./precompile_dilithium_core.sol";
import "./ZKNOX_dilithium_utils.sol";
import "./ZKNOX_SampleInBall.sol";
import "./ZKNOX_shake.sol";
import {
    q,
    ZKNOX_Expand,
    ZKNOX_Expand_Vec,
    ZKNOX_Expand_Mat,
    ZKNOX_Compact,
    omega,
    gamma_1_minus_beta
} from "./ZKNOX_dilithium_utils.sol";
import {console} from "forge-std/Test.sol";

import {useHintDilithium} from "./ZKNOX_hint.sol";

/**
 * @title Precompile-based ETH Dilithium Verification Contract
 * @notice ML-DSA (Dilithium) signature verification using EIP-7885 NTT precompiles
 * @dev Uses precompiles at addresses 0x12-0x15 for NTT operations:
 *      - 0x12: NTT_FW (Forward NTT)
 *      - 0x13: NTT_INV (Inverse NTT)
 *      - 0x14: NTT_VECMULMOD (Vector modular multiplication)
 *      - 0x15: NTT_VECADDMOD (Vector modular addition)
 */
contract precompile_ethdilithium {
    /**
     * @notice Verify a Dilithium signature
     * @param pk Public key
     * @param m Message bytes
     * @param signature Signature to verify
     * @param ctx Context bytes (must be <= 255 bytes)
     * @return True if signature is valid
     */
    function verify(PubKey memory pk, bytes memory m, Signature memory signature, bytes memory ctx)
        external
        view
        returns (bool)
    {
        // Step 1: check ctx length
        if (ctx.length > 255) {
            revert("ctx bytes must have length at most 255");
        }

        // Step 2: m_prime = 0x00 || len(ctx) || ctx || m
        bytes memory m_prime = abi.encodePacked(bytes1(0), bytes1(uint8(ctx.length)), ctx, m);

        // Step 3: delegate to internal verify
        return verify_internal(pk, m_prime, signature);
    }

    /**
     * @notice Internal verification logic using precompiles (LEGACY)
     * @dev Uses expand/compact cycles - kept for compatibility
     * @param pk Public key
     * @param m_prime Processed message
     * @param signature Signature to verify
     * @return True if signature is valid
     */
    function verify_internal(PubKey memory pk, bytes memory m_prime, Signature memory signature)
        internal
        view
        returns (bool)
    {
        uint256 i;
        uint256 j;

        // FIRST CORE STEP
        (bool foo, uint256 norm_h, uint256[][] memory h, uint256[][] memory z) = precompile_dilithium_core_1(signature);

        if (foo == false) {
            return false;
        }
        if (norm_h > omega) {
            return false;
        }
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 256; j++) {
                uint256 zij = z[i][j];
                if (zij > gamma_1_minus_beta && (q - zij) > gamma_1_minus_beta) {
                    return false;
                }
            }
        }

        // C_NTT - using precompile for forward NTT
        uint256[] memory c_ntt = sampleInBallKeccakPRNG(signature.c_tilde, tau, q);
        c_ntt = PrecompileNTT.PRECOMPILE_NTTFW(c_ntt);

        // t1_new
        uint256[][] memory t1_new = ZKNOX_Expand_Vec(pk.t1);

        // SECOND CORE STEP using precompiles
        bytes memory w_prime_bytes = precompile_dilithium_core_2(pk, z, c_ntt, h, t1_new);

        // FINAL HASH
        KeccakPRNG memory prng = initPRNG(abi.encodePacked(pk.tr, m_prime));
        bytes32 out1 = prng.pool;
        refill(prng);
        bytes32 out2 = prng.pool;
        prng = initPRNG(abi.encodePacked(out1, out2, w_prime_bytes));
        bytes32 final_hash = prng.pool;
        return final_hash == bytes32(signature.c_tilde);
    }

    /**
     * @notice Optimized internal verification using bytes-based operations
     * @dev Eliminates expand/compact cycles for significant gas savings
     *      Uses compact format directly with precompiles
     * @param pk Public key (with compact t1 and a_hat)
     * @param m_prime Processed message
     * @param signature Signature to verify
     * @return True if signature is valid
     */
    function verify_internal_optimized(PubKey memory pk, bytes memory m_prime, Signature memory signature)
        internal
        view
        returns (bool)
    {
        uint256 i;
        uint256 j;

        // FIRST CORE STEP - unpack signature components
        (bool foo, uint256 norm_h, uint256[][] memory h, uint256[][] memory z) = precompile_dilithium_core_1(signature);

        if (foo == false) {
            return false;
        }
        if (norm_h > omega) {
            return false;
        }

        // Check z norm bounds
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 256; j++) {
                uint256 zij = z[i][j];
                if (zij > gamma_1_minus_beta && (q - zij) > gamma_1_minus_beta) {
                    return false;
                }
            }
        }

        // C - sample challenge (NOT yet NTT transformed)
        // NTT will be applied inside core_2_optimized
        uint256[] memory c = sampleInBallKeccakPRNG(signature.c_tilde, tau, q);
        uint256[] memory c_compact = ZKNOX_Compact(c);

        // SECOND CORE STEP using optimized bytes-based operations
        // Note: pk.t1 and pk.a_hat are already in compact NTT domain
        bytes memory w_prime_bytes = precompile_dilithium_core_2_optimized(pk, z, c_compact, h);

        // FINAL HASH
        KeccakPRNG memory prng = initPRNG(abi.encodePacked(pk.tr, m_prime));
        bytes32 out1 = prng.pool;
        refill(prng);
        bytes32 out2 = prng.pool;
        prng = initPRNG(abi.encodePacked(out1, out2, w_prime_bytes));
        bytes32 final_hash = prng.pool;
        return final_hash == bytes32(signature.c_tilde);
    }

    /**
     * @notice Verify a Dilithium signature using optimized bytes-based operations
     * @param pk Public key
     * @param m Message bytes
     * @param signature Signature to verify
     * @param ctx Context bytes (must be <= 255 bytes)
     * @return True if signature is valid
     */
    function verifyOptimized(PubKey memory pk, bytes memory m, Signature memory signature, bytes memory ctx)
        external
        view
        returns (bool)
    {
        // Step 1: check ctx length
        if (ctx.length > 255) {
            revert("ctx bytes must have length at most 255");
        }

        // Step 2: m_prime = 0x00 || len(ctx) || ctx || m
        bytes memory m_prime = abi.encodePacked(bytes1(0), bytes1(uint8(ctx.length)), ctx, m);

        // Step 3: delegate to optimized internal verify
        return verify_internal_optimized(pk, m_prime, signature);
    }

    /**
     * @notice Legacy verify function (kept for compatibility)
     * @dev Uses original expand/compact cycles
     */
    function verifyLegacy(PubKey memory pk, bytes memory m, Signature memory signature, bytes memory ctx)
        external
        view
        returns (bool)
    {
        // Step 1: check ctx length
        if (ctx.length > 255) {
            revert("ctx bytes must have length at most 255");
        }

        // Step 2: m_prime = 0x00 || len(ctx) || ctx || m
        bytes memory m_prime = abi.encodePacked(bytes1(0), bytes1(uint8(ctx.length)), ctx, m);

        // Step 3: delegate to legacy internal verify
        return verify_internal(pk, m_prime, signature);
    }

    /**
     * @notice Ultra-optimized verification using bytes-based z processing
     * @dev Unpacks z directly to bytes format,
     *      eliminating uint256[][] intermediate storage (saves ~28KB memory)
     *
     * Gas optimization breakdown:
     * - Eliminates 4×256×32 = 32KB z array allocation
     * - Removes _encodeExpandedToBytes conversion
     * - Single-pass unpack with integrated norm check
     *
     * @param pk Public key (t1 must be pre-computed as NTT(t1 << d))
     * @param m_prime Processed message
     * @param signature Signature to verify
     * @return True if signature is valid
     */
    function verify_internal_bytes_optimized(PubKey memory pk, bytes memory m_prime, Signature memory signature)
        internal
        view
        returns (bool)
    {
        // FIRST CORE STEP - unpack with bytes-based z and integrated norm check
        (bool h_valid, uint256 norm_h, uint256[][] memory h, bool z_valid, bytes[4] memory z_bytes) =
            precompile_dilithium_core_1_bytes(signature);

        // Validate h unpacking
        if (!h_valid) {
            return false;
        }
        if (norm_h > omega) {
            return false;
        }

        // z norm check was done during unpacking
        if (!z_valid) {
            return false;
        }

        // C - sample challenge (NOT yet NTT transformed)
        // NTT will be applied inside core_2_bytes
        uint256[] memory c = sampleInBallKeccakPRNG(signature.c_tilde, tau, q);
        uint256[] memory c_compact = ZKNOX_Compact(c);

        // SECOND CORE STEP using bytes-based z
        // Note: pk.t1 must contain NTT(t1 << d) in compact form
        bytes memory w_prime_bytes = precompile_dilithium_core_2_bytes(pk, z_bytes, c_compact, h);

        // FINAL HASH
        KeccakPRNG memory prng = initPRNG(abi.encodePacked(pk.tr, m_prime));
        bytes32 out1 = prng.pool;
        refill(prng);
        bytes32 out2 = prng.pool;
        prng = initPRNG(abi.encodePacked(out1, out2, w_prime_bytes));
        bytes32 final_hash = prng.pool;
        return final_hash == bytes32(signature.c_tilde);
    }

    /**
     * @notice Verify with bytes-based z optimization
     * @dev Most gas-efficient verification method
     *      Requires pk.t1 = NTT(t1 << d) pre-computed
     * @param pk Public key
     * @param m Message bytes
     * @param signature Signature to verify
     * @param ctx Context bytes (must be <= 255 bytes)
     * @return True if signature is valid
     */
    function verifyBytesOptimized(PubKey memory pk, bytes memory m, Signature memory signature, bytes memory ctx)
        external
        view
        returns (bool)
    {
        // Step 1: check ctx length
        if (ctx.length > 255) {
            revert("ctx bytes must have length at most 255");
        }

        // Step 2: m_prime = 0x00 || len(ctx) || ctx || m
        bytes memory m_prime = abi.encodePacked(bytes1(0), bytes1(uint8(ctx.length)), ctx, m);

        // Step 3: delegate to bytes-optimized internal verify
        return verify_internal_bytes_optimized(pk, m_prime, signature);
    }
}
