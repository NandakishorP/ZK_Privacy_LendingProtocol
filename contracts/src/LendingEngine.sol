// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IStealthVault} from "./interface/IStealthVault.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ILpToken} from "./interface/ILpToken.sol";
import {IncrementalMerkleTree, Poseidon2} from "./IncrementalMerkleTree.sol";
import {console2} from "forge-std/console2.sol";
import {IVerifier} from "./interface/IVerifier.sol";
import {
    AutomationCompatibleInterface
} from "../lib/chainlink-brownie-contracts/contracts/src/v0.8/automation/interfaces/AutomationCompatibleInterface.sol";

contract LendingEngine is IncrementalMerkleTree,AutomationCompatibleInterface{
    // errors
    error LendingEngine__InvalidCollateralToken();
    error LendingEngine__UnknownRoot();
    error LendingEngine__CommitmentAlreadyUsed();
    error LendingEngine__VerificationFailed();
    error LendingEngine__CommitmentAlreadyExists();
    error LendingEngine__NoActiveLoanFound();
    error LendingEngine__InvalidDepositAmount();
    error LendingEngine__InvalidDepositToken();
    error LendingEngine__InvalidRepayAmount();
    error LendingEngine__AmountShouldBeGreaterThanZero();
    error LendingPoolContract__LpTokenMintFailed();
    error LendingEngine__LoanAlreadyLiquidated();
    error LendingEngine__HealthProofVerificationFailed();

    // events

    event LoanBorrowed(address indexed recepient, bytes32 nullifierHash_, uint256 timestamp);
    event LiquidityDeposited(
        address indexed user,
        address indexed tokenAddress,
        uint256 amountDeposited,
        uint256 lpTokenMinted
    );

    // interfaces
    IStealthVault stealthVault;

    // right now we only accept weth, will be modified later
    uint256 public s_collateralTokenId;

    address private lpToken;
    
    
    // only borrowing token supported for the mvp is the usdt
    address public s_borrowToken;

    bytes32[] private nullifierHashes;
    
    // immutable variables
    IVerifier public immutable i_collateralVerifier;
    IVerifier public immutable i_healthVerifier;
    mapping(bytes32 => bool) public s_nullifierHashes;
    mapping(address => uint256) public s_tokenDetailsofUser;
    mapping(bytes32 nullifierHash => uint256) public s_loanUpdateTime;
    
    // constant variables
    uint256 public constant MINIMUM_COLLATERIZATION_RATIO = 132;
    uint256 public constant LIQUIDATION_THRESHOLD = 80;
    uint256 public constant PRECISION = 1e18;

    using SafeERC20 for IERC20;

    struct Loan {
        uint256 borrowAmount;
        uint256 tokenId;
        uint256 minimumCollateralUsed;
        uint256 startTime;
        uint256 userBorrowIndex;
        bool isLiquidated;
        bool repaid;

    }

    mapping(bytes32 nullifierHash => Loan) private loanDetails;
    mapping(bytes32 commitment => bool) public s_commitments;
    mapping(address token => uint256 totaliquidityOfToken) private s_amountDeposited;
    mapping(address token => uint256 ) private s_amountBorrowed;
    mapping(address token => uint256 borrowerIndexOfToken)
        public s_borrowerIndex;
    mapping(address user => mapping(address token => uint256 amount)) s_depositDetailsOfUser;

    uint256 totalSupply;
    uint256 totalBorrowed;
    uint256 totalReserves;

    uint256 public constant PROOF_SUBMISSION_INTERVAL = 180 minutes;




    modifier isTokenAllowed(uint256 tokenId_) {
        if (tokenId_ != s_collateralTokenId) {
            revert LendingEngine__InvalidCollateralToken();
        }
        _;
    }

    modifier isGreaterThanZero(uint256 amount){
        if(amount <=0 ){
            revert LendingEngine__AmountShouldBeGreaterThanZero();
        }
        _;
    }



    constructor(address borrowToken_,address lpTokenAddress, address collateralVerifier_,uint256 collateralTokenId_,address stealthVault_,uint32 depth_,Poseidon2 hasher_, address healthProofVerifier_) IncrementalMerkleTree(depth_,hasher_) {
        s_borrowToken = borrowToken_;
        i_collateralVerifier = IVerifier(collateralVerifier_);
        i_healthVerifier = IVerifier(healthProofVerifier_);
        s_collateralTokenId = collateralTokenId_;
        stealthVault = IStealthVault(stealthVault_);
        lpToken = lpTokenAddress;
        s_borrowerIndex[borrowToken_] = 1e18;

    }

    function depositLiquidity(address token,uint256 amount) external {
        if(amount ==0){
            revert LendingEngine__InvalidDepositAmount();
        }

        if(address(token) != s_borrowToken){
            revert LendingEngine__InvalidDepositToken();
        }

        IERC20(s_borrowToken).safeTransferFrom(msg.sender,address(this),amount);
        uint256 currentTotalLiquidity = s_amountDeposited[s_borrowToken];
        uint256 totalSupplyOfLpToken = ILpToken(lpToken).totalSupply();
        uint256 amountOfLpTokensToMint;
        unchecked {
            amountOfLpTokensToMint = (totalSupplyOfLpToken == 0 ||
                totalSupply == 0)
                ? amount
                : (amount * totalSupplyOfLpToken) / totalSupply;
        }

        unchecked {
            s_depositDetailsOfUser[msg.sender][token] += amount;
            s_amountDeposited[token] += amount;
            totalSupply+=amount;
        }

        _mintLpTokens(msg.sender, amountOfLpTokensToMint);

        emit LiquidityDeposited(
            msg.sender,
            token,
            amount,
            amountOfLpTokensToMint
        );
    }



    function borrowLoan(
        bytes memory proof_,
        bytes32 root_,
        bytes32 nullifierHash_,
        uint256 borrowAmount_,
        uint256 assetPrice_,
        uint256 tokenId_,
        address payable recepientAddress,
        bytes32[] memory publicInputs
    ) external isTokenAllowed(tokenId_) {
        if(!stealthVault.isKnownRoot(root_)){
            revert LendingEngine__UnknownRoot();
        }
        nullifierHashes.push(nullifierHash_);
        if(s_nullifierHashes[nullifierHash_]){
            revert LendingEngine__CommitmentAlreadyUsed();
        }


      
        if(!i_collateralVerifier.verify(proof_,publicInputs)){
            revert LendingEngine__VerificationFailed();
        }

        s_nullifierHashes[nullifierHash_] = true;
        uint256 minimumCollateralUsed_ = getMinimumCollateral(borrowAmount_,assetPrice_);
        s_loanUpdateTime[nullifierHash_] = block.timestamp;
        loanDetails[nullifierHash_] = Loan({
            borrowAmount: borrowAmount_,
            tokenId:tokenId_,
            minimumCollateralUsed: minimumCollateralUsed_,
            startTime: block.timestamp,
            userBorrowIndex: s_borrowerIndex[s_borrowToken],
            isLiquidated:false,
            repaid: false
        });
        totalBorrowed+=borrowAmount_;
        

        IERC20(s_borrowToken).safeTransfer(recepientAddress,borrowAmount_);
        emit LoanBorrowed(recepientAddress,nullifierHash_,block.timestamp);
    }

    function getMinimumCollateral(uint256 borrowAmountUSDT,uint256 collateralPriceUSD) public pure returns(uint256 minimumCollateralUsed){
        minimumCollateralUsed = (borrowAmountUSDT * MINIMUM_COLLATERIZATION_RATIO) / (100 * collateralPriceUSD);
    }


    function repayLoan(
        bytes32 commitment_,
        uint256 amount_,
        bytes32 nullifierHash_
    ) external returns(uint32 insertedIndex){
        if(s_commitments[commitment_]){
            revert LendingEngine__CommitmentAlreadyExists();
        }
        Loan storage loan = loanDetails[nullifierHash_];
        if(loan.isLiquidated){
            revert LendingEngine__LoanAlreadyLiquidated();
        }
        uint256 borrowLoanAmount = loan.borrowAmount;
        if(borrowLoanAmount == 0){
            revert LendingEngine__NoActiveLoanFound();
        }
        uint256 scaledLoanAmount = (borrowLoanAmount * s_borrowerIndex[s_borrowToken]) /
            loan.userBorrowIndex;
        // we need to calculate the interest rate
        if(amount_<scaledLoanAmount){
            revert LendingEngine__InvalidRepayAmount();
        }
        IERC20(s_borrowToken).safeTransferFrom(msg.sender,address(this),amount_);
        totalBorrowed-=borrowLoanAmount;
        totalReserves+=scaledLoanAmount - borrowLoanAmount;
        loan.repaid = true;
        insertedIndex = _insert(commitment_);
    }

    function verifyCollateralHealth(bytes memory proof, bytes32[] memory publicInputs) external{
        if(!i_healthVerifier.verify(proof,publicInputs)){
            revert LendingEngine__HealthProofVerificationFailed();
        }
        if(!stealthVault.isKnownRoot(publicInputs[0])){
            revert LendingEngine__UnknownRoot();
        }
        s_loanUpdateTime[publicInputs[1]] = block.timestamp;
    }



    // pending implemnatation for the price spike

    function checkUpkeep(bytes calldata /* calldata */) external view override returns(bool upkeepNeeded, bytes memory performData){
        bytes32[] memory nullifierHashes_ = nullifierHashes;
        for(uint256 i=0;i< nullifierHashes_.length;i++){
            if(block.timestamp - s_loanUpdateTime[nullifierHashes_[i]]>PROOF_SUBMISSION_INTERVAL && !loanDetails[nullifierHashes[i]].repaid){
                return (true, abi.encode(nullifierHashes_[i]));
            }
        }
        return (false,"");
    }

    function performUpkeep(bytes calldata performData) external override{
        (bytes32 nullifierHash_) = abi.decode(performData,(bytes32));
        loanDetails[nullifierHash_].isLiquidated = true;
        stealthVault.liquidationCollateralTransfer(s_collateralTokenId,loanDetails[nullifierHash_].minimumCollateralUsed);
    }



    function _mintLpTokens(
        address to,
        uint256 amountToMint
    ) internal isGreaterThanZero(amountToMint) {
        if (!ILpToken(lpToken).mint(to, amountToMint)) {
            revert LendingPoolContract__LpTokenMintFailed();
        }
        s_tokenDetailsofUser[to] += amountToMint;
    }

    function getLoanDetails(bytes32 nullifierHash_) external returns(Loan memory){
        return loanDetails[nullifierHash_];
    }

    function getBorrowTokenAddress() external view returns(address){
        return s_borrowToken;
    }

    function getCollateralTokenId() external view returns(uint256){
        return s_collateralTokenId;
    }

    function getTotalDepositAmount(address token) external view returns(uint256){
        return s_amountDeposited[token];
    }

    function getTotalBorrowAmount(address token) external view returns(uint256){
        return s_amountBorrowed[token];
    }

    function getBorrowerIndex(address token) external view returns(uint256){
        return s_borrowerIndex[token];
    }

    function getTotalSupply() external returns(uint256){
        return totalSupply;
    }
    function getTotalBorrow() external returns(uint256){
        return totalBorrowed;
    }
    function getTotalReserves() external returns(uint256){
        return totalReserves;
    }
}
