pragma solidity 0.7.3;

contract BadRecipient {
  fallback () external {
    require(false, "this contract does not accept ETH");
  }
}
