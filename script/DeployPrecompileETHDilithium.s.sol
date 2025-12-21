pragma solidity ^0.8.25;

import {Script} from "../lib/forge-std/src/Script.sol";
import {BaseScript} from "./BaseScript.sol";
import "../src/precompile_ethdilithium.sol";

import {console} from "forge-std/Test.sol";

/**
 * @title Deploy script for precompile-based ETH Dilithium
 * @notice Deploys the precompile_ethdilithium contract which uses EIP-7885 NTT precompiles
 * @dev Requires a network that supports EIP-7885 precompiles at addresses:
 *      - 0x12: NTT_FW
 *      - 0x13: NTT_INV
 *      - 0x14: NTT_VECMULMOD
 *      - 0x15: NTT_VECADDMOD
 *
 * Usage:
 *   forge script script/DeployPrecompileETHDilithium.s.sol --rpc-url <RPC_URL> --broadcast
 */
contract Script_Deploy_Precompile_ETHDilithium is BaseScript {
    // SPDX-License-Identifier: MIT

    function run() external {
        vm.startBroadcast();

        bytes32 salty = keccak256(abi.encodePacked("ZKNOX_precompile_v0.2"));

        precompile_ethdilithium ETHDILITHIUM = new precompile_ethdilithium{salt: salty}();

        console.log("Deployed precompile_ethdilithium at:", address(ETHDILITHIUM));

        vm.stopBroadcast();
    }
}
