// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/DemoToken.sol";

/**
 * @title SimulateAttack
 * @notice End-to-end simulation:
 *   1. Baseline normal mints + transfers
 *   2. Suspicious privileged mint
 *   3. Staging transfer
 *   4. Exit transfer
 *
 * Run:  forge script script/SimulateAttack.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
 *
 * Anvil default accounts:
 *   [0] 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266  — deployer / owner / privileged actor
 *   [1] 0x70997970C51812dc3A010C7d01b50e0d17dc79C8  — user1
 *   [2] 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC  — user2
 *   [3] 0x90F79bf6EB2c4f870365E785982E1f101E93b906  — staging wallet
 *   [4] 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65  — exit wallet
 */
contract SimulateAttack is Script {
    // Anvil deterministic private keys
    uint256 constant OWNER_KEY    = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant USER1_KEY    = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 constant USER2_KEY    = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant STAGING_KEY  = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;

    address constant USER1   = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    address constant USER2   = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
    address constant STAGING = 0x90F79bf6EB2c4f870365E785982E1f101E93b906;
    address constant EXIT    = 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65;

    function run() external {
        // --- Read deployed token address from broadcast ---
        // We get the most recent deployment from the Deploy broadcast.
        // For simplicity, use the deterministic CREATE address for deployer nonce 0.
        address owner = vm.addr(OWNER_KEY);

        // Compute the deterministic contract address (deployer nonce = 0 at deploy time)
        // On Anvil the deployer starts at nonce 0, so the token is at:
        address tokenAddr = vm.computeCreateAddress(owner, 0);
        DemoToken token = DemoToken(tokenAddr);

        console.log("Using DemoToken at:", tokenAddr);
        console.log("Owner:", owner);

        // ============ BASELINE NORMAL ACTIVITY ============

        // Normal mint 1: owner mints 100 tokens to user1
        vm.startBroadcast(OWNER_KEY);
        token.mint(USER1, 100 ether);
        vm.stopBroadcast();
        console.log("[BASELINE] Minted 100 DEMO to user1");

        // Normal mint 2: owner mints 50 tokens to user2
        vm.startBroadcast(OWNER_KEY);
        token.mint(USER2, 50 ether);
        vm.stopBroadcast();
        console.log("[BASELINE] Minted 50 DEMO to user2");

        // Normal transfer: user1 sends 10 tokens to user2
        vm.startBroadcast(USER1_KEY);
        token.transfer(USER2, 10 ether);
        vm.stopBroadcast();
        console.log("[BASELINE] user1 -> user2: 10 DEMO");

        // Normal transfer: user2 sends 5 tokens to user1
        vm.startBroadcast(USER2_KEY);
        token.transfer(USER1, 5 ether);
        vm.stopBroadcast();
        console.log("[BASELINE] user2 -> user1: 5 DEMO");

        // ============ SUSPICIOUS INCIDENT ============

        // Step 1: Privileged actor (owner) performs abnormally large mint — 1,000,000 tokens to self
        vm.startBroadcast(OWNER_KEY);
        token.mint(owner, 1_000_000 ether);
        vm.stopBroadcast();
        console.log("[SUSPICIOUS] Owner minted 1,000,000 DEMO to self");

        // Step 2: Transfer minted tokens to staging wallet
        vm.startBroadcast(OWNER_KEY);
        token.transfer(STAGING, 1_000_000 ether);
        vm.stopBroadcast();
        console.log("[SUSPICIOUS] Owner -> staging: 1,000,000 DEMO");

        // Step 3: Staging wallet moves tokens to exit wallet
        vm.startBroadcast(STAGING_KEY);
        token.transfer(EXIT, 1_000_000 ether);
        vm.stopBroadcast();
        console.log("[SUSPICIOUS] staging -> exit: 1,000,000 DEMO");

        console.log("===== SIMULATION COMPLETE =====");
    }
}
