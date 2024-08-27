// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GlobalPasskeySystem {
    struct Passkey {
        bytes publicKey;
        uint256 lastUsedNonce;
        bool isActive;
    }

    mapping(address => Passkey) public userPasskeys;
    mapping(bytes32 => bool) public usedChallenges;

    event PasskeyRegistered(address indexed user, bytes publicKey);
    event AuthenticationChallenge(address indexed user, bytes32 challenge);
    event AuthenticationSuccessful(address indexed user);

    function registerPasskey(bytes memory _publicKey) public {
        require(!userPasskeys[msg.sender].isActive, "Passkey already registered");
        userPasskeys[msg.sender] = Passkey(_publicKey, 0, true);
        emit PasskeyRegistered(msg.sender, _publicKey);
    }

    function generateAuthChallenge() public returns (bytes32) {
        require(userPasskeys[msg.sender].isActive, "No passkey registered");
        bytes32 challenge = keccak256(abi.encodePacked(msg.sender, block.timestamp, userPasskeys[msg.sender].lastUsedNonce));
        emit AuthenticationChallenge(msg.sender, challenge);
        return challenge;
    }

    function verifyAuthentication(bytes32 _challenge, bytes memory _signature) public {
        require(userPasskeys[msg.sender].isActive, "No passkey registered");
        require(!usedChallenges[_challenge], "Challenge already used");

        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHash = keccak256(abi.encodePacked(prefix, _challenge));

        // Recover the signer's address from the signature
        address recoveredAddress = recoverSigner(prefixedHash, _signature);

        // Verify that the recovered address matches the stored public key
        require(verifySignature(userPasskeys[msg.sender].publicKey, recoveredAddress), "Invalid signature");

        usedChallenges[_challenge] = true;
        userPasskeys[msg.sender].lastUsedNonce++;

        emit AuthenticationSuccessful(msg.sender);
    }

    function recoverSigner(bytes32 _hash, bytes memory _signature) internal pure returns (address) {
        require(_signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");

        return ecrecover(_hash, v, r, s);
    }

    function verifySignature(bytes memory _publicKey, address _recoveredAddress) internal pure returns (bool) {
        // In a real implementation, you would compare the recovered address
        // with the address derived from the stored public key.
        // This is a simplified placeholder.
        return true;
    }
}