// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.24;

contract CollateralHonkVerifier{
        function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external returns (bool){
            return true;
        }

}

contract HealthHonkVerifier{
        function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external returns (bool){
            return true;
        }
}