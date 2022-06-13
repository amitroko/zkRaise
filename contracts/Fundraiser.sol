pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/ownership/Ownable.sol";
import "./MerkleTreeWithHistory.sol";

interface IVerifier {
    function verifyProof(bytes memory _proof, uint156[6] memory _input) external returns (bool);
}

contract Fundraiser is ReentrancyGuard, Ownable, MerkleTreeWithHistory {
    IVerifier public immutable verifier;
    uint public deployed;
    uint public fundraisingPeriodLength;
    uint public fundraisingGoal;
    uint[] public tiers;

    mapping(bytes32 => bool) public nullifierHashes;
    mapping(bytes32 => bool) public commitments;

    event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
    event FundWithdrawal(address to, bytes32 nullifierHash);

    /**
      @dev Constructor
      @param _verifier the address of SNARK verifier for this contract
      @param _hasher the address of MiMC hash contract
      @param _merkleTreeHeight the height of deposits' Merkle Tree
      @param _fundraisingPeriodLength the length of the fundraising period, which begins on contract deployment
      @param _fundraisingGoal the amount of ETH that must be deposited for a successful raise
      @param _tiers the acceptable amounts of ETH that can be deposited at a time
    */
    constructor(
        IVerifier _verifier,
        IHasher _hasher,
        uint32 _merkleTreeHeight,
        uint _fundraisingPeriodLength,
        uint _fundraisingGoal,
        uint[] memory _tiers
    ) MerkleTreeWithHistory(_merkleTreeHeight, _hasher) {
        require(_tiers.length == 0, "Must have at least one fundraising tier.");
        require(_tiers.length <= 4, "Must have four or less fundraising tiers.");

        verifier = _verifier;
        deployed = block.timestamp;
        fundraisingPeriodLength = _fundraisingPeriodLength;
        fundraisingGoal = _fundraisingGoal;
        tiers = _tiers;
    }

    /**
      @dev Deposit a fundraising contribution into the contract. The message value must match a fundraising tier.
      @param _commitment the note commitment
    */
    function deposit(bytes32 _commitment) external payable nonReentrant {
        require(!commitments[_commitment], "The commitment has already been submitted.");
        require(matchesTier(msg.value), "The message value did not match a fundraising tier");

        uint32 insertedIndex = _insert(_commitment);
        commitments[_commitment] = true;
        
        emit Deposit(_commitment, insertedIndex, block.timestamp);
    }

    /**
      @dev Withdraw a contribution if the fundraising goal was not met
      @param _proof zkSNARK proof data
      @param _root Merkle root of all deposits in contract
      @param _nullifierHash hash of unique deposit nullifier
      @param _recipient recipient of the funds
      @param _tier the fundraising tier that the contributor met
    */
    function withdraw(
        bytes calldata _proof,
        bytes32 _root,
        bytes32 _nullifierHash,
        address payable _recipient,
        uint _tier
    ) external nonReentrant {
        require(block.timestamp - deployed >= fundraisingPeriodLength,
            "The fundraising period is still in progress.");
        require(address(this).balance < fundraisingGoal,
            "The fundraising goal was met.");
        require(!nullifierHashes[_nullifierHash], "The note has been already spent.");
        require(isKnownRoot(_root), "Cannot find this merkle root.");
        require(
            verifier.verifyProof(
                _proof,
                [uint256(_root), uint256(_nullifierHash), uint256(_recipient), uint256(_tier)]
            ),
            "Invalid withdrawal proof."
        );

        nullifierHashes[_nullifierHash] = true;
        (bool success, ) = _recipient.call{ value: tiers[_tier - 1] }("");
        require(success, "Payment failed.");

        emit Withdrawal(_recipient, _nullifierHash);
    }

    /**
      @dev Allow the owner to withdraw the contract's balance if the fundraising goal is met. 
    */
    function witdrawRaisedFunds() public onlyOwner {
        require(block.timestamp - deployed >= fundraisingPeriodLength,
            "The fundraising period is still in progress.");
        require(address(this).balance >= fundraisingGoal,
            "The fundraising goal was not met.");

        payable(msg.sender).transfer(address(this).balance);
    }

    /**
      @dev Validate that the message value matches a fundraising tier
      @param _val the message value
    */
    function matchesTier(uint _val) internal view returns (bool) {
        for (uint i = 0; i < tiers.length; i++) {
            if (val == tiers[i]) {
                return true;
            }
        }
        return false;
    }
}