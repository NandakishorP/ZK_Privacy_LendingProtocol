// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Script,console2}  from "forge-std/Script.sol";
import {HonkVerifier} from "../Verifiers/Verifier_LoanHealth.sol";
import {IVerifier} from "../src/interface/IVerifier.sol";
contract DeployLoanHealthVerifier is Script{
    function run() public {

        vm.startBroadcast();
        HonkVerifier verifier = new HonkVerifier();
        vm.stopBroadcast();
        console2.log("loan health verifier",address(verifier));
    }
}