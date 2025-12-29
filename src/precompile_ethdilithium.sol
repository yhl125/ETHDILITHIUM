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
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {
    precompile_dilithium_core_1_bytes,
    precompile_dilithium_core_2_bytes
} from "./precompile_dilithium_core.sol";
import {sampleInBallKeccakPrng} from "./ZKNOX_SampleInBall.sol";
import {KeccakPrng, initPrng, refill} from "./ZKNOX_keccak_prng.sol";
import {q, compact, OMEGA, GAMMA_1_MINUS_BETA, TAU, PubKey, Signature, slice} from "./ZKNOX_dilithium_utils.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {IPKContract} from "./ZKNOX_PKContract.sol";

/**
 * @title Precompile-based ETH Dilithium Verification Contract
 * @notice ML-DSA (Dilithium) signature verification using EIP-7885 NTT precompiles
 * @dev Uses precompiles at addresses 0x12-0x15 for NTT operations:
 *      - 0x12: NTT_FW (Forward NTT)
 *      - 0x13: NTT_INV (Inverse NTT)
 *      - 0x14: NTT_VECMULMOD (Vector modular multiplication)
 *      - 0x15: NTT_VECADDMOD (Vector modular addition)
 */
contract precompile_ethdilithium is IERC7913SignatureVerifier {
    /**
     * @notice Verify a Dilithium signature (ERC-7913 style with IPKContract)
     * @param pk Public key address as bytes
     * @param m Message bytes
     * @param signature Packed signature bytes
     * @param ctx Context bytes (must be <= 255 bytes)
     * @return True if signature is valid
     */
    function verify(bytes memory pk, bytes memory m, bytes memory signature, bytes memory ctx)
        external
        view
        returns (bool)
    {
        // Fetch the public key from the address `pk`
        address pubKeyAddress;
        assembly {
            pubKeyAddress := mload(add(pk, 20))
        }
        PubKey memory publicKey = IPKContract(pubKeyAddress).getPublicKey();

        // Step 1: check ctx length
        if (ctx.length > 255) {
            revert("ctx bytes must have length at most 255");
        }

        // Step 2: mPrime = 0x00 || len(ctx) || ctx || m
        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(uint8(ctx.length)), ctx, m);

        Signature memory sig =
            Signature({cTilde: slice(signature, 0, 32), z: slice(signature, 32, 2304), h: slice(signature, 2336, 84)});

        // Step 3: delegate to internal verify
        return verifyInternal(publicKey, mPrime, sig);
    }

    /**
     * @notice Verify a Dilithium signature (ERC-7913 selector style)
     * @param pk Public key address as bytes
     * @param m Message hash (bytes32)
     * @param signature Packed signature bytes
     * @return bytes4 selector on success, 0xFFFFFFFF on failure
     */
    function verify(bytes calldata pk, bytes32 m, bytes calldata signature) external view returns (bytes4) {
        // Fetch the public key from the address `pk`
        address pubKeyAddress;
        assembly {
            pubKeyAddress := shr(96, calldataload(pk.offset))
        }
        PubKey memory publicKey = IPKContract(pubKeyAddress).getPublicKey();

        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(0), m);

        Signature memory sig =
            Signature({cTilde: slice(signature, 0, 32), z: slice(signature, 32, 2304), h: slice(signature, 2336, 84)});

        // Step 3: delegate to internal verify
        if (verifyInternal(publicKey, mPrime, sig)) {
            return IERC7913SignatureVerifier.verify.selector;
        }
        return 0xFFFFFFFF;
    }

    /**
     * @notice Verify a Dilithium signature (direct struct input)
     * @param pk Public key struct
     * @param m Message bytes
     * @param signature Signature struct
     * @param ctx Context bytes (must be <= 255 bytes)
     * @return True if signature is valid
     */
    function verify(PubKey memory pk, bytes memory m, Signature memory signature, bytes memory ctx)
        external
        view
        returns (bool)
    {
        if (ctx.length > 255) {
            revert("ctx bytes must have length at most 255");
        }
        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(uint8(ctx.length)), ctx, m);
        return verifyInternal(pk, mPrime, signature);
    }

    /**
     * @notice Internal bytes-optimized verification
     * @dev Uses precompile_dilithium_core_1_bytes and precompile_dilithium_core_2_bytes
     *      Maximum optimization - avoids most expand/compact conversions
     */
    function verifyInternal(PubKey memory pk, bytes memory mPrime, Signature memory signature)
        internal
        view
        returns (bool)
    {
        // FIRST CORE STEP - bytes version with integrated norm check
        (bool foo, uint256 normH, uint256[][] memory h, bool zValid, bytes[4] memory zBytes) =
            precompile_dilithium_core_1_bytes(signature);

        if (foo == false) {
            return false;
        }
        if (normH > OMEGA) {
            return false;
        }
        if (zValid == false) {
            return false;
        }

        // C_NTT - sample and keep as compact
        uint256[] memory cExpanded = sampleInBallKeccakPrng(signature.cTilde, TAU, q);
        uint256[] memory cCompact = compact(cExpanded);

        // SECOND CORE STEP - bytes version
        bytes memory wPrimeBytes = precompile_dilithium_core_2_bytes(pk, zBytes, cCompact, h);

        // FINAL HASH
        KeccakPrng memory prng = initPrng(abi.encodePacked(pk.tr, mPrime));
        bytes32 out1 = prng.pool;
        refill(prng);
        bytes32 out2 = prng.pool;
        prng = initPrng(abi.encodePacked(out1, out2, wPrimeBytes));
        bytes32 finalHash = prng.pool;
        return finalHash == bytes32(signature.cTilde);
    }
}
