// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
interface IStealthVault{
    function deposit(
        address token_,
        uint256 amount_,
        bytes32 commitment_
    ) external returns(uint32);
    function isKnownRoot(bytes32 _root) external view returns (bool);
    function liquidationCollateralTransfer(uint256 s_collateralTokenId, uint256 amount) external;
}