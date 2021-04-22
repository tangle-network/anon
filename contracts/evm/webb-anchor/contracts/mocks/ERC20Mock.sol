pragma solidity 0.7.3;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ERC20Mock is ERC20 {
  constructor() ERC20("DAIMock", "DAIM") public {
  }

  function mint(address account, uint256 amount) external {
    _mint(account, amount);
  }
}
