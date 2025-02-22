// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public lastWinnerAmount;
    address public lastWinner;
    
    constructor() {
        owner = msg.sender;
    }

    // **1. Reentrancy Vulnerability**
    function withdraw() public {
        require(balances[msg.sender] > 0, "No balance to withdraw");
        
        // Sends Ether before updating state (vulnerable to reentrancy)
        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    // **2. Unchecked External Call Vulnerability**
    function sendTo(address payable _recipient) public payable {
        // External call without verifying success
        _recipient.call{value: msg.value}("");
    }

    // **3. Integer Overflow & Underflow (Older Solidity Versions)**
    function subtract(uint256 a, uint256 b) public pure returns (uint256) {
        return a - b; // Unsafe subtraction (use SafeMath in older versions)
    }

    // **4. Unprotected Owner-Only Function**
    function changeOwner(address newOwner) public {
        owner = newOwner; // No access control, anyone can become the owner
    }

    // **5. Predictable Randomness (Vulnerable to Front-Running)**
    function guessNumber(uint256 guess) public payable {
        require(msg.value == 1 ether, "Send exactly 1 ETH");
        
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % 10;
        
        if (guess == random) {
            lastWinner = msg.sender;
            lastWinnerAmount = address(this).balance;
            payable(msg.sender).transfer(address(this).balance);
        }
    }

    // **6. Front-Running Vulnerability**
    function bid() public payable {
        require(msg.value > lastWinnerAmount, "Bid higher to win");
        lastWinner = msg.sender;
        lastWinnerAmount = msg.value;
    }

    // **7. Missing Fallback Function**
    // Contract cannot receive direct Ether transfers

    // **8. Hardcoded Private Data Exposure**
    string private secret = "SuperSecretPassword123"; // Accessible via blockchain analysis

    // **9. No Withdrawal Limit**
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // **10. Unchecked Return Value**
    function unsafeTransfer(address payable _to, uint256 _amount) public {
        _to.call{value: _amount}(""); // Ignoring return value, potential loss of funds
    }
}
