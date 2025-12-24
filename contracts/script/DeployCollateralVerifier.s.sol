// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Script,console2}  from "forge-std/Script.sol";
import {HonkVerifier} from "../Verifiers/Verifier_CollateralDeposit.sol";
import {IVerifier} from "../src/interface/IVerifier.sol";
contract DeployCollateralVerifier is Script{
    function run() public {
        IVerifier verifier = IVerifier(
            address(new HonkVerifier())
        );

        console2.log(address(verifier));
    }
}