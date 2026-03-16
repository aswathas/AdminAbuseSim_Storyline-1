// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DemoToken
 * @notice Minimal ERC20-like token for forensic simulation.
 *         Owner-restricted mint, standard Transfer event.
 *         Intentionally simple — not a full ERC20 implementation.
 */
contract DemoToken {
    string public name = "DemoToken";
    string public symbol = "DEMO";
    uint8  public decimals = 18;

    address public owner;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "DemoToken: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Owner-only mint — the vector for privileged abuse.
     */
    function mint(address to, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    /**
     * @notice Standard transfer.
     */
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "DemoToken: insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
