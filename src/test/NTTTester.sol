// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title NTTTester - Test contract for pure Solidity NTT functions
 * @notice Exposes ZKNOX_NTTFW, ZKNOX_NTTINV for external testing
 */

import "../ZKNOX_NTT_dilithium.sol";
import {
    ZKNOX_VECMULMOD,
    ZKNOX_VECADDMOD,
    ZKNOX_VECSUBMOD,
    q
} from "../ZKNOX_dilithium_utils.sol";

contract NTTTester {
    /**
     * @notice Forward NTT using pure Solidity implementation
     * @param a Input polynomial (256 coefficients)
     * @return NTT-transformed polynomial
     */
    function nttForward(uint256[] memory a) external pure returns (uint256[] memory) {
        return ZKNOX_NTTFW(a);
    }

    /**
     * @notice Inverse NTT using pure Solidity implementation
     * @param a Input polynomial in NTT domain
     * @return Inverse NTT-transformed polynomial
     */
    function nttInverse(uint256[] memory a) external pure returns (uint256[] memory) {
        return ZKNOX_NTTINV(a);
    }

    /**
     * @notice Vector modular multiplication
     * @param a First vector
     * @param b Second vector
     * @return Element-wise product mod q
     */
    function vecMulMod(uint256[] memory a, uint256[] memory b) external pure returns (uint256[] memory) {
        return ZKNOX_VECMULMOD(a, b);
    }

    /**
     * @notice Vector modular addition
     * @param a First vector
     * @param b Second vector
     * @return Element-wise sum mod q
     */
    function vecAddMod(uint256[] memory a, uint256[] memory b) external pure returns (uint256[] memory) {
        return ZKNOX_VECADDMOD(a, b);
    }

    /**
     * @notice Vector modular subtraction
     * @param a First vector
     * @param b Second vector
     * @return Element-wise difference mod q
     */
    function vecSubMod(uint256[] memory a, uint256[] memory b) external pure returns (uint256[] memory) {
        return ZKNOX_VECSUBMOD(a, b);
    }

    /**
     * @notice Get the modulus q
     */
    function getQ() external pure returns (uint256) {
        return q;
    }

    /**
     * @notice Full round-trip test: NTT forward then inverse
     * @param a Input polynomial
     * @return Should equal original input
     */
    function nttRoundTrip(uint256[] memory a) external pure returns (uint256[] memory) {
        uint256[] memory ntt_a = ZKNOX_NTTFW(a);
        return ZKNOX_NTTINV(ntt_a);
    }
}
