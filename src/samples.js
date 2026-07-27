export const vulnerableSample = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function emergencySweep(address payable recipient) external {
        require(tx.origin == owner, "not authorized");
        recipient.call{value: address(this).balance}("");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        balances[msg.sender] = 0;
    }
}`;

export const fixedSample = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SaferVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function emergencySweep(address payable recipient) external {
        require(msg.sender == owner, "not authorized");
        (bool success, ) = recipient.call{value: address(this).balance}("");
        require(success, "transfer failed");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
    }
}`;
