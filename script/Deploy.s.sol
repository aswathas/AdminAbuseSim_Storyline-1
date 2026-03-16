// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/DemoToken.sol";

/**
 * @title Deploy
 * @notice Deploys DemoToken to local Anvil.
 *         Run:  forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
 */
contract Deploy is Script {
    function run() external {
        // Anvil account 0
        uint256 deployerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

        vm.startBroadcast(deployerKey);
        DemoToken token = new DemoToken();
        vm.stopBroadcast();

        console.log("DemoToken deployed at:", address(token));
    }
}
