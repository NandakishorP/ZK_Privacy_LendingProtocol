// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;
import {IERC20} from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {IncrementalMerkleTree, Poseidon2} from "./IncrementalMerkleTree.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ILendingEngine} from "./interface/ILendingEngine.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IVerifier } from "./interface/IVerifier.sol";
contract StealthVault is IncrementalMerkleTree,Ownable{

    using SafeERC20 for IERC20;

    mapping(uint256 collateralTokenId => address) public s_collateralIdToAddress;

    // errors
    error StealthVault__CommitmentAlreadyExists();
    error StealthVault__InvalidToken(address token);
    error StealthVault__UnknownRoot();
    error LendingEngine__CommitmentAlreadyUsed();
    error StealthVault__InvalidRepaymentProof();

    // mappings
    mapping(bytes32 commitment => bool) public s_commitments;
    mapping(bytes32 nullifierHash => bool) public s_nullifierHashes;
    address public immutable i_ethTokenAddress;

    ILendingEngine lendingEngine;
    IVerifier public immutable i_repaymentVerifier;

    // events

    event Deposit(bytes32 commitment, uint32 insertedIndex, uint256 timeStamp);
    event DepositWithdrawn(address withdrawer,uint256 amount);

    // later need to be modified to upgradable
    constructor(address ethTokenAddress_,uint32 depth_,Poseidon2 hasher_, address repaymentVerifier_, address collateralTokenAddress) IncrementalMerkleTree(depth_,hasher_) Ownable(msg.sender) {
        i_ethTokenAddress = ethTokenAddress_;
        i_repaymentVerifier = IVerifier(repaymentVerifier_);
        s_collateralIdToAddress[0] = collateralTokenAddress;
    } 

    // need to modify later to accept mulitple tokens
    modifier allowListedTokens(address token) {
        if(token!=i_ethTokenAddress){
            revert StealthVault__InvalidToken(token);
        }
        _;
    }

    function setLendingEngine(address lendingEngine_) external onlyOwner{
        lendingEngine = ILendingEngine(lendingEngine_);
    }
    function deposit(
        address token_,
        uint256 amount_,
        bytes32 commitment_
    ) external allowListedTokens(token_) returns(uint32){

        if(s_commitments[commitment_]) {
            revert StealthVault__CommitmentAlreadyExists();
        }
        IERC20(token_).safeTransferFrom(msg.sender, address(this), amount_);
        uint32 insertedIndex = _insert(commitment_);
        s_commitments[commitment_] = true;
        emit Deposit(commitment_,insertedIndex,block.timestamp);
        return insertedIndex;
    }

    function withdraw(address token_, uint256 amount, bytes memory proof_,bytes32 root_1,bytes32 root_2, bytes32 nullifierHash,address withdrawAddress, bytes32[] memory publicInputs ) external allowListedTokens(token_){
        // root one is the root in the repayment merkle tree and root 2 is the roon in the deposit merkle tree
        if(lendingEngine.isKnownRoot(root_1)){
            revert StealthVault__UnknownRoot();
        }
        if(isKnownRoot(root_2))
        if(s_nullifierHashes[nullifierHash]){
            revert LendingEngine__CommitmentAlreadyUsed();
        }
        if(!i_repaymentVerifier.verify(proof_,publicInputs)){
            revert StealthVault__InvalidRepaymentProof();
        }
        s_nullifierHashes[nullifierHash] = true;
        IERC20(token_).safeTransfer(withdrawAddress,amount);
        emit DepositWithdrawn(withdrawAddress,amount);
    }

    function liquidationCollateralTransfer(uint256 s_collateralTokenId, uint256 amount) external onlyOwner{
        IERC20(s_collateralIdToAddress[s_collateralTokenId]).safeTransfer(msg.sender,amount);
    }   
}
