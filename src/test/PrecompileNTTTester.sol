// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title PrecompileNTTTester - Test contract for EIP-7885 NTT precompiles
 * @notice Exposes precompile-based NTT functions for external testing
 */

import {PrecompileNTT} from "../precompile_NTT.sol";
import {q} from "../ZKNOX_dilithium_utils.sol";

contract PrecompileNTTTester {
    /**
     * @notice Forward NTT using precompile (0x12)
     * @param a Input polynomial (256 coefficients)
     * @return NTT-transformed polynomial
     */
    function nttForward(uint256[] memory a) external view returns (uint256[] memory) {
        return PrecompileNTT.PRECOMPILE_NTTFW(a);
    }

    /**
     * @notice Inverse NTT using precompile (0x13)
     * @param a Input polynomial in NTT domain
     * @return Inverse NTT-transformed polynomial
     */
    function nttInverse(uint256[] memory a) external view returns (uint256[] memory) {
        return PrecompileNTT.PRECOMPILE_NTTINV(a);
    }

    /**
     * @notice Vector modular multiplication using precompile (0x14)
     * @param a First vector
     * @param b Second vector
     * @return Element-wise product mod q
     */
    function vecMulMod(uint256[] memory a, uint256[] memory b) external view returns (uint256[] memory) {
        return PrecompileNTT.PRECOMPILE_VECMULMOD(a, b);
    }

    /**
     * @notice Vector modular addition using precompile (0x15)
     * @param a First vector
     * @param b Second vector
     * @return Element-wise sum mod q
     */
    function vecAddMod(uint256[] memory a, uint256[] memory b) external view returns (uint256[] memory) {
        return PrecompileNTT.PRECOMPILE_VECADDMOD(a, b);
    }

    /**
     * @notice Vector modular subtraction (pure Solidity, no precompile for this)
     * @param a First vector
     * @param b Second vector
     * @return Element-wise difference mod q
     */
    function vecSubMod(uint256[] memory a, uint256[] memory b) external pure returns (uint256[] memory) {
        require(a.length == b.length, "Array lengths must match");
        uint256[] memory res = new uint256[](a.length);
        for (uint256 i = 0; i < a.length; i++) {
            res[i] = addmod(a[i], q - b[i], q);
        }
        return res;
    }

    /**
     * @notice Get the modulus q
     */
    function getQ() external pure returns (uint256) {
        return q;
    }

    /**
     * @notice Full round-trip test: NTT forward then inverse using precompiles
     * @param a Input polynomial
     * @return Should equal original input
     */
    function nttRoundTrip(uint256[] memory a) external view returns (uint256[] memory) {
        uint256[] memory ntt_a = PrecompileNTT.PRECOMPILE_NTTFW(a);
        return PrecompileNTT.PRECOMPILE_NTTINV(ntt_a);
    }

    /**
     * @notice Direct precompile call for debugging - returns raw bytes
     * @param input Raw input bytes for precompile
     * @return success Whether the call succeeded
     * @return output Raw output bytes from precompile
     */
    function rawNttFwCall(bytes memory input) external view returns (bool success, bytes memory output) {
        (success, output) = address(0x12).staticcall(input);
    }

    /**
     * @notice Direct precompile call for NTT_INV
     */
    function rawNttInvCall(bytes memory input) external view returns (bool success, bytes memory output) {
        (success, output) = address(0x13).staticcall(input);
    }

    /**
     * @notice Direct precompile call for VECMULMOD
     */
    function rawVecMulModCall(bytes memory input) external view returns (bool success, bytes memory output) {
        (success, output) = address(0x14).staticcall(input);
    }

    /**
     * @notice Direct precompile call for VECADDMOD
     */
    function rawVecAddModCall(bytes memory input) external view returns (bool success, bytes memory output) {
        (success, output) = address(0x15).staticcall(input);
    }

    /**
     * @notice Encode input for precompile (for debugging)
     * @param a Input array
     * @return Encoded bytes ready for precompile
     */
    function encodeForPrecompile(uint256[] memory a) external pure returns (bytes memory) {
        return PrecompileNTT.encodeInput(a);
    }

    /**
     * @notice Encode two vectors for VECMULMOD/VECADDMOD
     */
    function encodeVecForPrecompile(uint256[] memory a, uint256[] memory b) external pure returns (bytes memory) {
        return PrecompileNTT.encodeVecInput(a, b);
    }
}
