// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract HumanityProtocol is Ownable {
    struct UserData {
        bytes32 merkleRoot;
        uint256 proofCount;
    }

    mapping(address => UserData) public users;
    uint256 public totalProofs;

    event MerkleRootUpdated(address indexed user, bytes32 newMerkleRoot, uint256 proofCount);

    constructor(address initialOwner) Ownable(initialOwner) {}

    function updateMerkleRoot(bytes32 _newMerkleRoot, uint256 _newProofCount) external {
        require(_newProofCount > 0, "Proof count must be greater than zero");
        
        UserData storage userData = users[msg.sender];
        
        totalProofs = totalProofs - userData.proofCount + _newProofCount;
        userData.merkleRoot = _newMerkleRoot;
        userData.proofCount = _newProofCount;

        emit MerkleRootUpdated(msg.sender, _newMerkleRoot, _newProofCount);
    }

    function verifyProof(address _user, bytes32[] memory _proof, bytes32 _leaf) external view returns (bool) {
        UserData storage userData = users[_user];
        require(userData.merkleRoot != bytes32(0), "User is not verified");
        return MerkleProof.verify(_proof, userData.merkleRoot, _leaf);
    }

    function getMerkleRoot(address _user) external view returns (bytes32) {
        return users[_user].merkleRoot;
    }

    function isUserVerified(address _user) external view returns (bool) {
        return users[_user].merkleRoot != bytes32(0);
    }

    function getUserProofCount(address _user) external view returns (uint256) {
        return users[_user].proofCount;
    }
}