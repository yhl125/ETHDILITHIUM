// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "../lib/forge-std/src/Script.sol";
import {console} from "forge-std/Test.sol";
import "../src/test/NTTTester.sol";
import "../src/test/PrecompileNTTTester.sol";

/**
 * @title Deploy script for NTT Tester contracts
 * @notice Deploys both Solidity and Precompile NTT testers for comparison
 *
 * Usage:
 *   forge script script/DeployNTTTesters.s.sol --rpc-url <RPC_URL> --broadcast
 */
contract Script_Deploy_NTTTesters is Script {
    function run() external {
        vm.startBroadcast();

        bytes32 salty = keccak256(abi.encodePacked("NTTTester_v0.2"));

        // Deploy Solidity NTT Tester
        NTTTester solidityTester = new NTTTester{salt: salty}();
        console.log("NTTTester (Solidity) deployed at:", address(solidityTester));

        // Deploy Precompile NTT Tester
        PrecompileNTTTester precompileTester = new PrecompileNTTTester{salt: salty}();
        console.log("PrecompileNTTTester deployed at:", address(precompileTester));

        vm.stopBroadcast();

        // Output addresses for use in test scripts
        console.log("");
        console.log("=== Contract Addresses ===");
        console.log("SOLIDITY_TESTER=%s", address(solidityTester));
        console.log("PRECOMPILE_TESTER=%s", address(precompileTester));
    }
}
