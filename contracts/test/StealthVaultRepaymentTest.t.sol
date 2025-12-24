// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test, console2} from "forge-std/Test.sol";
import {StealthVault, Poseidon2} from "../src/StealthVault.sol";
import {ERC20Mock} from "lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {LendingEngine} from "../src/LendingEngine.sol";
import {LpToken} from "../src/tokens/LpToken.sol";
import {RepaymentProofHelper, RepaymentProofParams} from "./RepaymentHelper.sol";
import {CollateralHonkVerifier} from "./CollateralHonkVerifier.sol";
import {HonkVerifier as RepaymentHonkVerifier} from "../Verifiers/Verifier_LoanRepayment.sol";
import {IVerifier} from "../src/interface/IVerifier.sol";
import {MockV3Aggregator} from "./mocks/MockV3Aggregator.sol";
import {PriceSnapShot} from "../src/PriceSnapShot.sol";
contract StealthVaultTestBorrow is Test {
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
    IVerifier repaymentVerifier;
    MockV3Aggregator oracle;
    uint256 public constant ETH_PRICE = 1000;
    uint256 public MINIMUM_COLLATERIZATION_RATIO = 132;
    uint256 public ACTUAL_COLLATERIZATION_RATIO = 150;
    RepaymentProofHelper repaymentProofHelper;

    function setUp() public {
        collateralVerifier = IVerifier(address(new CollateralHonkVerifier()));
        repaymentVerifier = IVerifier(address(new RepaymentHonkVerifier()));
        posiedon2 = new Poseidon2();
        weth = new ERC20Mock();
        usdt = new ERC20Mock();
        ERC20Mock(address(weth)).mint(user, DEPOSIT_AMOUNT * 10);
        lpToken = new LpToken();
        repaymentProofHelper = new RepaymentProofHelper();
        oracle = new MockV3Aggregator(8, int256(ETH_PRICE * 1e8));

        stealthVault = new StealthVault(
            address(weth),
            16,
            posiedon2,
            address(repaymentVerifier),
            address(weth)
        );
        lendingEngine = new LendingEngine(
            address(oracle),
            address(usdt),
            address(lpToken),
            address(collateralVerifier),
            WETH_TOKEN_ID,
            address(stealthVault),
            16,
            posiedon2,
            address(collateralVerifier)
        );
        ERC20Mock(address(usdt)).mint(
            address(lendingEngine),
            DEPOSIT_AMOUNT * 100000
        );
        stealthVault.setLendingEngine(address(lendingEngine));
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
        string[] memory inputs = new string[](16 + leaves.length);
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
        inputs[12] = vm.toString(depositProofParams.epochCommitment);
        inputs[13] = vm.toString(depositProofParams.epoch);
        inputs[14] = vm.toString(depositProofParams.roundId);
        inputs[15] = vm.toString(depositProofParams.price);

        for (uint256 i = 0; i < leaves.length; i++) {
            inputs[16 + i] = vm.toString(leaves[i]);
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

   

    function _getRepaymentCommitment()
        internal
        returns (bytes32 commitment, bytes32 nullifier, bytes32 secret)
    {
        string[] memory inputs = new string[](3);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "js-scripts/generateRepaymentCommitment.ts";
        bytes memory result = vm.ffi(inputs);
        (commitment, nullifier, secret) = abi.decode(
            result,
            (bytes32, bytes32, bytes32)
        );
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
        bytes32 epochCommitment;
        uint256 epoch;
        uint64 roundId;
        uint256 price;
    }

    function testRepayment() public {
        // 1. Setup: Deposit collateral and get commitment
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

        lendingEngine.callPerformUpKeep();

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

        uint256 currentEpoch = lendingEngine.getCurrentEpoch();
        PriceSnapShot.SnapShot memory snapshot = lendingEngine.getCurrentSnapShot();
        

        DepositProofParams memory params = DepositProofParams({
            nullifierDeposit: nullifier,
            secretDeposit: secret,
            borrowAmount: borrowAmount,
            assetPrice: ETH_PRICE,
            tokenId: WETH_TOKEN_ID,
            recipient: user,
            minCollateralizationRatio: MINIMUM_COLLATERIZATION_RATIO,
            actualCollateralizationRatio: ACTUAL_COLLATERIZATION_RATIO,
            collateralAmount: DEPOSIT_AMOUNT,
            epochCommitment: snapshot.commitment,
            epoch: currentEpoch,
            roundId: snapshot.roundId,
            price: snapshot.price
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

        // 3. Repay the loan
        (
            bytes32 commitmentRepayment,
            bytes32 nullifierRepayment,
            bytes32 secretRepayment
        ) = _executeLoanRepayment(publicInputs);

        // 4. Withdraw collateral
        _executeCollateralWithdrawal(
            nullifier,
            secret,
            borrowAmount,
            nullifierRepayment,
            secretRepayment,
            commitment,
            commitmentRepayment,
            publicInputs
        );
    }

    // ========== Helper Functions ==========


    

    

    function _executeLoanRepayment(
        bytes32[] memory borrowPublicInputs
    ) private returns (bytes32 commitment, bytes32 nullifier, bytes32 secret) {
        // Get repayment commitment
        (commitment, nullifier, secret) = _getRepaymentCommitment();

        // Calculate scaled repayment amount
        LendingEngine.Loan memory loan = lendingEngine.getLoanDetails(
            borrowPublicInputs[1]
        );
        uint256 borrowerIndex = lendingEngine.getBorrowerIndex(address(usdt));
        uint256 scaledAmount = (loan.borrowAmount * borrowerIndex) /
            loan.userBorrowIndex;

        // Execute repayment
        vm.startPrank(user);
        ERC20Mock(usdt).approve(address(lendingEngine), scaledAmount);
        lendingEngine.repayLoan(
            commitment,
            scaledAmount,
            borrowPublicInputs[1]
        );
        vm.stopPrank();
    }

    function _executeCollateralWithdrawal(
        bytes32 nullifierDeposit,
        bytes32 secretDeposit,
        uint256 borrowAmount,
        bytes32 nullifierRepayment,
        bytes32 secretRepayment,
        bytes32 commitmentDeposit,
        bytes32 commitmentRepayment,
        bytes32[] memory borrowPublicInputs
    ) private {
        // Setup leaves
        bytes32[] memory leavesDeposit = new bytes32[](1);
        leavesDeposit[0] = commitmentDeposit;

        bytes32[] memory leavesRepayment = new bytes32[](1);
        leavesRepayment[0] = commitmentRepayment;

        // Generate repayment proof
        (
            bytes memory repaymentProof,
            bytes32[] memory repaymentPublicInputs
        ) = _generateRepaymentProof(
                nullifierDeposit,
                secretDeposit,
                borrowAmount,
                nullifierRepayment,
                secretRepayment,
                leavesDeposit,
                leavesRepayment
            );

        // Withdraw collateral
        vm.prank(user);
        stealthVault.withdraw(
            address(weth),
            DEPOSIT_AMOUNT,
            repaymentProof,
            borrowPublicInputs[0],
            borrowPublicInputs[3],
            borrowPublicInputs[1],
            user,
            repaymentPublicInputs
        );
    }

    function _generateRepaymentProof(
        bytes32 nullifierDeposit,
        bytes32 secretDeposit,
        uint256 borrowAmount,
        bytes32 nullifierRepayment,
        bytes32 secretRepayment,
        bytes32[] memory leavesDeposit,
        bytes32[] memory leavesRepayment
    ) private returns (bytes memory proof, bytes32[] memory publicInputs) {
        RepaymentProofParams memory params = RepaymentProofParams({
            nullifierDeposit: nullifierDeposit,
            secretDeposit: secretDeposit,
            borrowAmount: borrowAmount,
            assetPrice: ETH_PRICE,
            tokenId: WETH_TOKEN_ID,
            recepient: user,
            minCollateralizationRatio: MINIMUM_COLLATERIZATION_RATIO,
            actualCollateralizationRatio: ACTUAL_COLLATERIZATION_RATIO,
            collateralAmount: DEPOSIT_AMOUNT,
            nullifierRepayment: nullifierRepayment,
            secretRepayment: secretRepayment,
            withdrawAmount: DEPOSIT_AMOUNT
        });

        return
            repaymentProofHelper.getRepaymentProof(
                params,
                leavesDeposit,
                leavesRepayment
            );
    }

    
}
