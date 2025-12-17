// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test, console2} from "forge-std/Test.sol";
import {StealthVault, Poseidon2} from "../src/StealthVault.sol";
import {ERC20Mock} from "lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {LendingEngine} from "../src/LendingEngine.sol";
import {LpToken} from "../src/tokens/LpToken.sol";
import {CollateralHonkVerifier, HealthHonkVerifier} from "./CollateralHonkVerifier.sol";
import {IVerifier} from "../src/interface/IVerifier.sol";

contract StealthVaultTest is Test {
    StealthVault stealthVault;
    Poseidon2 posiedon2;
    ERC20Mock weth;
    ERC20Mock usdt;
    LpToken lpToken;
    uint256 public constant WETH_TOKEN_ID = 0;
    address user = makeAddr("user");
    address user1 = makeAddr("user1");
    uint256 public constant DEPOSIT_AMOUNT = 1e18;
    LendingEngine lendingEngine;
    IVerifier collateralVerifier;
    IVerifier healthVerifier;
    uint256 public constant ETH_PRICE = 1000;
    uint256 public MINIMUM_COLLATERIZATION_RATIO = 132;
    uint256 public ACTUAL_COLLATERIZATION_RATIO = 150;
    uint256 public constant LIQUIDATION_THRESHOLD = 80;

    function setUp() public {
        collateralVerifier = IVerifier(address(new CollateralHonkVerifier()));
        healthVerifier = IVerifier(address(new HealthHonkVerifier()));
        posiedon2 = new Poseidon2();
        weth = new ERC20Mock();
        usdt = new ERC20Mock();
        ERC20Mock(address(weth)).mint(user, DEPOSIT_AMOUNT * 10);
        lpToken = new LpToken();
        stealthVault = new StealthVault(
            address(weth),
            16,
            posiedon2,
            address(collateralVerifier),
            address(weth)
        );
        lendingEngine = new LendingEngine(
            address(usdt),
            address(lpToken),
            address(collateralVerifier),
            WETH_TOKEN_ID,
            address(stealthVault),
            16,
            posiedon2,
            address(healthVerifier)
        );
        stealthVault.transferOwnership(address(lendingEngine));
        ERC20Mock(address(usdt)).mint(
            address(lendingEngine),
            DEPOSIT_AMOUNT * 100000
        );
    }

    function _getCommitment()
        internal
        returns (bytes32 commitment, bytes32 nullifier, bytes32 secret)
    {
        string[] memory inputs = new string[](5);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "js-scripts/generateCommitment.ts";
        inputs[3] = vm.toString(DEPOSIT_AMOUNT);
        inputs[4] = vm.toString(WETH_TOKEN_ID);
        bytes memory result = vm.ffi(inputs);
        (commitment, nullifier, secret) = abi.decode(
            result,
            (bytes32, bytes32, bytes32)
        );
    }

    function _getProof(
        DepositProofParams memory depositProofParams,
        bytes32[] memory leaves
    ) internal returns (bytes memory proof, bytes32[] memory publicInputs) {
        string[] memory inputs = new string[](12 + leaves.length);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "js-scripts/generateProof.ts";
        inputs[3] = vm.toString(depositProofParams.nullifierDeposit);
        inputs[4] = vm.toString(depositProofParams.secretDeposit);
        inputs[5] = vm.toString(depositProofParams.borrowAmount);
        inputs[6] = vm.toString(depositProofParams.assetPrice);
        inputs[7] = vm.toString(depositProofParams.tokenId);
        inputs[8] = vm.toString(
            bytes32(uint256(uint160(depositProofParams.recipient)))
        );
        inputs[9] = vm.toString(depositProofParams.minCollateralizationRatio);
        inputs[10] = vm.toString(
            depositProofParams.actualCollateralizationRatio
        );
        inputs[11] = vm.toString(depositProofParams.collateralAmount);
        for (uint256 i = 0; i < leaves.length; i++) {
            inputs[12 + i] = vm.toString(leaves[i]);
        }
        bytes memory result = vm.ffi(inputs);
        (proof, publicInputs) = abi.decode(result, (bytes, bytes32[]));
    }

    function testDeposit() public {
        (
            bytes32 commitment,
            bytes32 nullifier,
            bytes32 secret
        ) = _getCommitment();
        vm.startPrank(user);
        ERC20Mock(weth).approve(address(stealthVault), DEPOSIT_AMOUNT);
        stealthVault.deposit(address(weth), DEPOSIT_AMOUNT, commitment);
        vm.stopPrank();
    }

    function testBorrow() public {
        (
            bytes32 commitment,
            bytes32 nullifier,
            bytes32 secret
        ) = _getCommitment();

        // 2) User deposits collateral (1 ETH)
        vm.startPrank(user);
        ERC20Mock(weth).approve(address(stealthVault), DEPOSIT_AMOUNT);
        stealthVault.deposit(address(weth), DEPOSIT_AMOUNT, commitment);
        vm.stopPrank();

        // 3) Setup Merkle tree leaf
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = commitment;

        // ---------------------------
        // 🔥 Correct Max Borrow Math
        // ---------------------------

        // Convert collateral to USD
        uint256 collateralValueUSD = (DEPOSIT_AMOUNT * ETH_PRICE) / 1e18;

        // maxBorrow = (collateralValueUSD * 100) / 132
        uint256 maxBorrow = (collateralValueUSD * 100) /
            MINIMUM_COLLATERIZATION_RATIO;
        // ≈ 757 USDT

        // Use maxBorrow for test
        uint256 borrowAmount = maxBorrow;

        DepositProofParams memory params = DepositProofParams({
            nullifierDeposit: nullifier,
            secretDeposit: secret,
            borrowAmount: borrowAmount,
            assetPrice: ETH_PRICE,
            tokenId: WETH_TOKEN_ID,
            recipient: user,
            minCollateralizationRatio: MINIMUM_COLLATERIZATION_RATIO,
            actualCollateralizationRatio: ACTUAL_COLLATERIZATION_RATIO,
            collateralAmount: DEPOSIT_AMOUNT
        });

        // 4) Generate the proof
        (bytes memory proof, bytes32[] memory publicInputs) = _getProof(
            params,
            leaves
        );

        // 5) Borrow
        vm.prank(user);

        lendingEngine.borrowLoan(
            proof,
            publicInputs[0],
            publicInputs[1],
            borrowAmount,
            ETH_PRICE,
            WETH_TOKEN_ID,
            payable(address(uint160(uint256(publicInputs[6])))),
            publicInputs
        );

        // 6) Validate user1 received the borrowed USDT
        uint256 userBalance = ERC20Mock(usdt).balanceOf(user1);

        assertEq(userBalance, borrowAmount, "Borrowed amount mismatch");
    }

    struct DepositProofParams {
        bytes32 nullifierDeposit;
        bytes32 secretDeposit;
        uint256 borrowAmount;
        uint256 assetPrice;
        uint256 tokenId;
        address recipient;
        uint256 minCollateralizationRatio;
        uint256 actualCollateralizationRatio;
        uint256 collateralAmount;
    }

    // ========== Helper Functions ==========

    function _setupCollateralDeposit()
        private
        returns (bytes32 commitment, bytes32 nullifier, bytes32 secret)
    {
        (commitment, nullifier, secret) = _getCommitment();

        vm.startPrank(user);
        ERC20Mock(weth).approve(address(stealthVault), DEPOSIT_AMOUNT);
        stealthVault.deposit(address(weth), DEPOSIT_AMOUNT, commitment);
        vm.stopPrank();
    }

    function _executeBorrow(
        bytes32 commitmentDeposit,
        bytes32 nullifierDeposit,
        bytes32 secretDeposit
    ) private returns (uint256 borrowAmount, bytes32[] memory publicInputs) {
        // Setup Merkle tree
        bytes32[] memory leavesDeposit = new bytes32[](1);
        leavesDeposit[0] = commitmentDeposit;

        // Calculate max borrow amount
        borrowAmount = _calculateMaxBorrow();

        // Generate proof
        bytes memory proof;
        (proof, publicInputs) = _generateBorrowProof(
            nullifierDeposit,
            secretDeposit,
            borrowAmount,
            leavesDeposit
        );

        // Execute borrow
        vm.prank(user);
        lendingEngine.borrowLoan(
            proof,
            publicInputs[0],
            publicInputs[1],
            borrowAmount,
            ETH_PRICE,
            WETH_TOKEN_ID,
            payable(address(uint160(uint256(publicInputs[6])))),
            publicInputs
        );
    }

    function _calculateMaxBorrow() private view returns (uint256) {
        uint256 collateralValueUSD = (DEPOSIT_AMOUNT * ETH_PRICE) / 1e18;
        return (collateralValueUSD * 100) / MINIMUM_COLLATERIZATION_RATIO;
    }

    function _generateBorrowProof(
        bytes32 nullifierDeposit,
        bytes32 secretDeposit,
        uint256 borrowAmount,
        bytes32[] memory leaves
    ) private returns (bytes memory proof, bytes32[] memory publicInputs) {
        DepositProofParams memory depositParams = DepositProofParams({
            nullifierDeposit: nullifierDeposit,
            secretDeposit: secretDeposit,
            borrowAmount: borrowAmount,
            assetPrice: ETH_PRICE,
            tokenId: WETH_TOKEN_ID,
            recipient: user,
            minCollateralizationRatio: MINIMUM_COLLATERIZATION_RATIO,
            actualCollateralizationRatio: ACTUAL_COLLATERIZATION_RATIO,
            collateralAmount: DEPOSIT_AMOUNT
        });

        return _getProof(depositParams, leaves);
    }

    struct HealthProofParams {
        bytes32 nullifier;
        bytes32 secret;
        uint256 borrowAmount;
        uint256 assetPrice;
        uint256 liquidationThreshold;
        uint256 tokenId;
        uint256 collateralAmount;
    }

    function _getHealthProof(
        HealthProofParams memory healthProofParams,
        bytes32[] memory leaves
    ) internal returns(bytes memory proof, bytes32[] memory publicInputs) {
        string[] memory inputs = new string[](10 + leaves.length);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "js-scripts/generateHealthProof.ts";
        inputs[3] = vm.toString(healthProofParams.nullifier);
        inputs[4] = vm.toString(healthProofParams.secret);
        inputs[5] = vm.toString(healthProofParams.borrowAmount);
        inputs[6] = vm.toString(healthProofParams.assetPrice);
        inputs[7] = vm.toString(healthProofParams.tokenId);
        inputs[8] = vm.toString(healthProofParams.liquidationThreshold);
        inputs[9] = vm.toString(healthProofParams.collateralAmount);
        for (uint256 i = 0; i < leaves.length; i++) {
            inputs[10 + i] = vm.toString(leaves[i]);
        }
        bytes memory result = vm.ffi(inputs);
        (proof, publicInputs) = abi.decode(result, (bytes, bytes32[]));
    }

    function testLiquidation() public {
        (
            bytes32 commitment,
            bytes32 nullifier,
            bytes32 secret
        ) = _getCommitment();

        // 2) User deposits collateral (1 ETH)
        vm.startPrank(user);
        ERC20Mock(weth).approve(address(stealthVault), DEPOSIT_AMOUNT);
        stealthVault.deposit(address(weth), DEPOSIT_AMOUNT, commitment);
        vm.stopPrank();

        // 3) Setup Merkle tree leaf
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = commitment;

        // ---------------------------
        // 🔥 Correct Max Borrow Math
        // ---------------------------

        // Convert collateral to USD
        uint256 collateralValueUSD = (DEPOSIT_AMOUNT * ETH_PRICE) / 1e18;

        // maxBorrow = (collateralValueUSD * 100) / 132
        uint256 maxBorrow = (collateralValueUSD * 100) /
            MINIMUM_COLLATERIZATION_RATIO;
        // ≈ 757 USDT

        // Use maxBorrow for test
        uint256 borrowAmount = maxBorrow;

        DepositProofParams memory params = DepositProofParams({
            nullifierDeposit: nullifier,
            secretDeposit: secret,
            borrowAmount: borrowAmount,
            assetPrice: ETH_PRICE,
            tokenId: WETH_TOKEN_ID,
            recipient: user,
            minCollateralizationRatio: MINIMUM_COLLATERIZATION_RATIO,
            actualCollateralizationRatio: ACTUAL_COLLATERIZATION_RATIO,
            collateralAmount: DEPOSIT_AMOUNT
        });

        // 4) Generate the proof
        (bytes memory proof, bytes32[] memory publicInputs) = _getProof(
            params,
            leaves
        );

        // 5) Borrow
        vm.prank(user);

        lendingEngine.borrowLoan(
            proof,
            publicInputs[0],
            publicInputs[1],
            borrowAmount,
            ETH_PRICE,
            WETH_TOKEN_ID,
            payable(address(uint160(uint256(publicInputs[6])))),
            publicInputs
        );

        vm.warp(block.timestamp + 120 minutes);
        HealthProofParams memory healthProofParams = HealthProofParams({
            nullifier: nullifier,
            secret: secret,
            borrowAmount: borrowAmount,
            assetPrice: ETH_PRICE,
            liquidationThreshold: LIQUIDATION_THRESHOLD,
            tokenId: WETH_TOKEN_ID,
            collateralAmount: DEPOSIT_AMOUNT
        });

        (bytes memory proof1, bytes32[] memory publicInputs1) = _getHealthProof(
            healthProofParams,
            leaves
        );

        lendingEngine.verifyCollateralHealth(proof1, publicInputs1);

        vm.warp(block.timestamp + 60 minutes);

        (bool upkeepNeeded1, bytes memory performData1) = lendingEngine
            .checkUpkeep("");

        assertEq(upkeepNeeded1, false);

        vm.warp(block.timestamp + 240 minutes);
        (bool upkeepNeeded2, bytes memory performData2) = lendingEngine
            .checkUpkeep("");

        assertEq(upkeepNeeded2, true);
    }
}
