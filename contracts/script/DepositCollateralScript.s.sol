// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {IStealthVault} from "../src/interface/IStealthVault.sol";

contract DepositCollateralScript is Script {
    function run() public {

        address user = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        address lendingEngine = 0x9A676e781A523b5d0C0e43731313A708CB607508;
        address stealthvault = 0xA51c1fc2f0D1a1b8494Ed1FE312d7C3a78Ed91C0;
        vm.startBroadcast(user);


        

        vm.stopBroadcast();
    }
}